// SPDX-License-Identifier: GPL-2.0
/*
 * CPUFreq governor based on scheduler-provided CPU utilization data.
 *
 * Copyright (C) 2016, Intel Corporation
 * Author: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
 */

#include <trace/hooks/sched.h>
#include <linux/cpufreq.h>
#include <linux/sched/cputime.h>
#include "sched.h"
#include <uapi/linux/sched/types.h>
#include <linux/kthread.h>
#include <linux/irq_work.h>

#ifdef CONFIG_CGROUP_SCHED
/**
 * rq_has_topapp_running - returns true if the current task on rq
 * belongs to the top-app cgroup.
 */
static inline bool rq_has_topapp_running(struct rq *rq)
{
	struct task_struct *curr = rq->curr;

	if (!curr || is_idle_task(curr))
		return false;

	return task_is_ui_critical(curr);
}
#else
static inline bool rq_has_topapp_running(struct rq *rq) { return false; }
#endif

#define IOWAIT_BOOST_MIN	(SCHED_CAPACITY_SCALE / 8)

/*
 * WALT-style window-max filter: retain the peak PELT utilization seen across
 * the last SWELT_WINDOWS x SWELT_WINDOW_NS of time so that a short
 * burst keeps frequency elevated for ~100 ms instead of decaying immediately.
 */
#define SWELT_WINDOWS		5
#define SWELT_WINDOW_NS		25000000ULL  /* 20 ms */
#define SWELT_FILTER_MAX_CPU	2	/* filter applies to CPUs 0..2 (little cluster) */

struct swelt_lt {
	unsigned long	history[SWELT_WINDOWS];
	int		idx;
	u64		window_start;
	unsigned long	window_peak;  /* max seen in current window */
};

static DEFINE_PER_CPU(struct swelt_lt, sg_lt);

struct swelt_tunables {
	struct gov_attr_set	attr_set;
	unsigned int		up_rate_limit_us;
	unsigned int		down_rate_limit_us;

	/* SAG: window-max filter */
	bool			sag_filter_enabled;
	unsigned int		sag_windows;
	unsigned int		sag_window_duration_us;
	unsigned int		sag_freq_floor_khz;
	unsigned int		sag_filter_max_cpu;

#ifdef CONFIG_CGROUP_SCHED
	/* SAG: scheduler-assisted (ui_critical) boost */
	bool			sag_boost_enabled;
	unsigned int		sag_up_rate_limit_us;
	unsigned int		sag_freq_min_khz;
	unsigned int		sag_util_clamp_pct;
#endif
};

struct swelt_policy {
	struct cpufreq_policy	*policy;

	struct swelt_tunables	*tunables;
	struct list_head	tunables_hook;

	raw_spinlock_t		update_lock;
	u64			last_freq_update_time;
	s64			min_rate_limit_ns;
	s64			up_freq_update_delay_ns;
	s64			down_freq_update_delay_ns;
	unsigned int		next_freq;
	unsigned int		cached_raw_freq;

	/* The next fields are only needed if fast switch cannot be used: */
	struct			irq_work irq_work;
	struct			kthread_work work;
	struct			mutex work_lock;
	struct			kthread_worker worker;
	struct task_struct	*thread;
	bool			work_in_progress;

	bool			limits_changed;
	bool			need_freq_update;

	/* SAG: mirrored from tunables at start time */
	bool			sag_filter_enabled;
	unsigned int		sag_windows;
	unsigned int		sag_window_duration_us;
	unsigned int		sag_freq_floor_khz;
	unsigned int		sag_filter_max_cpu;

#ifdef CONFIG_CGROUP_SCHED
	bool			sag_boost_enabled;
	s64			sag_up_freq_update_delay_ns;
	unsigned int		sag_freq_min_khz;
	unsigned int		sag_util_clamp_pct;
#endif
};

struct swelt_cpu {
	struct update_util_data	update_util;
	struct swelt_policy	*sg_policy;
	unsigned int		cpu;

	bool			iowait_boost_pending;
	unsigned int		iowait_boost;
	u64			last_update;

	unsigned long		util;
	unsigned long		bw_dl;
	unsigned long		max;

	/* The field below is for single-CPU policies only: */
#ifdef CONFIG_NO_HZ_COMMON
	unsigned long		saved_idle_calls;
#endif
};

static DEFINE_PER_CPU(struct swelt_cpu, swelt_cpu);

/************************ Governor internals ***********************/

static bool swelt_should_update_freq(struct swelt_policy *sg_policy, u64 time)
{
	s64 delta_ns;

	/*
	 * Since cpufreq_update_util() is called with rq->lock held for
	 * the @target_cpu, our per-CPU data is fully serialized.
	 *
	 * However, drivers cannot in general deal with cross-CPU
	 * requests, so while get_next_freq() will work, our
	 * swelt_update_commit() call may not for the fast switching platforms.
	 *
	 * Hence stop here for remote requests if they aren't supported
	 * by the hardware, as calculating the frequency is pointless if
	 * we cannot in fact act on it.
	 *
	 * This is needed on the slow switching platforms too to prevent CPUs
	 * going offline from leaving stale IRQ work items behind.
	 */
	if (!cpufreq_this_cpu_can_update(sg_policy->policy))
		return false;

	if (unlikely(sg_policy->limits_changed)) {
		sg_policy->limits_changed = false;
		sg_policy->need_freq_update = true;
		return true;
	}

	delta_ns = time - sg_policy->last_freq_update_time;

	return delta_ns >= sg_policy->min_rate_limit_ns;
}

static bool swelt_up_down_rate_limit(struct swelt_policy *sg_policy, u64 time,
				     unsigned int next_freq)
{
	s64 delta_ns;

	delta_ns = time - sg_policy->last_freq_update_time;

	if (next_freq > sg_policy->next_freq &&
	    delta_ns < sg_policy->up_freq_update_delay_ns)
		return true;

	if (next_freq < sg_policy->next_freq &&
	    delta_ns < sg_policy->down_freq_update_delay_ns)
		return true;

	return false;
}

static bool swelt_update_next_freq(struct swelt_policy *sg_policy, u64 time,
				   unsigned int next_freq)
{
	if (sg_policy->need_freq_update) {
		sg_policy->need_freq_update = false;
		/*
		 * The policy limits have changed, but if the return value of
		 * cpufreq_driver_resolve_freq() after applying the new limits
		 * is still equal to the previously selected frequency, the
		 * driver callback need not be invoked unless the driver
		 * specifically wants that to happen on every update of the
		 * policy limits.
		 */
		if (sg_policy->next_freq == next_freq &&
		    !cpufreq_driver_test_flags(CPUFREQ_NEED_UPDATE_LIMITS))
			return false;

		if (swelt_up_down_rate_limit(sg_policy, time, next_freq)) {
			sg_policy->cached_raw_freq = 0;
			return false;
		}
	} else if (sg_policy->next_freq == next_freq) {
		return false;
	}

	sg_policy->next_freq = next_freq;
	sg_policy->last_freq_update_time = time;

	return true;
}

static void swelt_deferred_update(struct swelt_policy *sg_policy)
{
	if (!sg_policy->work_in_progress) {
		sg_policy->work_in_progress = true;
		irq_work_queue(&sg_policy->irq_work);
	}
}

/**
 * get_next_freq - Compute a new frequency for a given cpufreq policy.
 * @sg_policy: swelt policy object to compute the new frequency for.
 * @util: Current CPU utilization.
 * @max: CPU capacity.
 *
 * If the utilization is frequency-invariant, choose the new frequency to be
 * proportional to it, that is
 *
 * next_freq = C * max_freq * util / max
 *
 * Otherwise, approximate the would-be frequency-invariant utilization by
 * util_raw * (curr_freq / max_freq) which leads to
 *
 * next_freq = C * curr_freq * util_raw / max
 *
 * Take C = 1.25 for the frequency tipping point at (util / max) = 0.8.
 *
 * The lowest driver-supported frequency which is equal or greater than the raw
 * next_freq (as calculated above) is returned, subject to policy min/max and
 * cpufreq driver limitations.
 */
static unsigned int get_next_freq(struct swelt_policy *sg_policy,
				  unsigned long util, unsigned long max)
{
	struct cpufreq_policy *policy = sg_policy->policy;
	unsigned int freq = arch_scale_freq_invariant() ?
			policy->cpuinfo.max_freq : policy->cur;
	unsigned long next_freq = 0;

	if (next_freq)
		freq = next_freq;
	else {
		freq = map_util_freq(util, freq, max);

		if (freq == sg_policy->cached_raw_freq && !sg_policy->need_freq_update)
			return sg_policy->next_freq;

		sg_policy->cached_raw_freq = freq;
	}

	sg_policy->cached_raw_freq = freq;
	return cpufreq_driver_resolve_freq(policy, freq);
}

/**
 * swelt_filter_util - WALT-style window-max filter over PELT utilization.
 * @sg_cpu:    the swelt_cpu whose history to consult
 * @pelt_util: raw PELT utilization just computed by swelt_get_util()
 *
 * Returns the maximum utilization seen across the last sag_windows
 * windows (each sag_window_duration_us wide) plus the current partial
 * window. This prevents premature frequency downscaling after a short
 * burst.
 *
 * When sag_filter_enabled is false the raw pelt_util is returned unchanged.
 */
static unsigned long swelt_filter_util(struct swelt_cpu *sg_cpu,
				       unsigned long pelt_util)
{
	struct swelt_policy *sg_policy = sg_cpu->sg_policy;
	struct swelt_lt *w = &per_cpu(sg_lt, sg_cpu->cpu);
	unsigned int windows;
	u64 window_ns;
	u64 now = ktime_get_ns();
	unsigned long max_util = 0;
	int i;

	/* Kill-switch: bypass the filter entirely */
	if (!sg_policy->sag_filter_enabled)
		return pelt_util;

	windows   = sg_policy->sag_windows;
	window_ns = (u64)sg_policy->sag_window_duration_us * NSEC_PER_USEC;

	/* Track peak within the current window */
	if (pelt_util > w->window_peak)
		w->window_peak = pelt_util;

	/* Window expired — commit it to history and start a new one */
	if (now - w->window_start >= window_ns) {
		u64 elapsed = now - w->window_start;

		/* If CPU was idle for a long time, flush all history */
		if (elapsed >= windows * window_ns) {
			for (i = 0; i < SWELT_WINDOWS; i++)
				w->history[i] = 0;
			w->idx = 0;
			w->window_start = now;
		} else {
			/* Roll the window(s) */
			while (now - w->window_start >= window_ns) {
				w->history[w->idx % SWELT_WINDOWS] = w->window_peak;
				w->idx++;
				w->window_peak = 0;
				w->window_start += window_ns;
			}
		}
		w->window_peak = pelt_util;
	}

	/* Return max across all retained windows */
	for (i = 0; i < SWELT_WINDOWS; i++)
		if (w->history[i] > max_util)
			max_util = w->history[i];

	/* Also include the current partial window */
	return max(max_util, w->window_peak);
}

static void swelt_get_util(struct swelt_cpu *sg_cpu)
{
	struct rq *rq = cpu_rq(sg_cpu->cpu);
	struct swelt_policy *sg_policy = sg_cpu->sg_policy;

	sg_cpu->max   = arch_scale_cpu_capacity(sg_cpu->cpu);
	sg_cpu->bw_dl = cpu_bw_dl(rq);
	sg_cpu->util  = effective_cpu_util(sg_cpu->cpu, cpu_util_cfs(sg_cpu->cpu),
					   FREQUENCY_UTIL, NULL);

	/*
	 * Apply WALT-style window-max filter to prevent premature downscaling
	 * after a utilization burst. Only promote util to the filtered value
	 * when the resolved frequency is at or above sag_freq_floor_khz.
	 * The filter is restricted to CPUs <= sag_filter_max_cpu.
	 */
	if (sg_policy->sag_filter_enabled &&
	    sg_cpu->cpu <= sg_policy->sag_filter_max_cpu) {
		unsigned long swelt_u = swelt_filter_util(sg_cpu, sg_cpu->util);
		struct cpufreq_policy *policy = sg_policy->policy;
		unsigned int freq = arch_scale_freq_invariant() ?
					policy->cpuinfo.max_freq : policy->cur;

		freq = map_util_freq(swelt_u, freq, sg_cpu->max);

		if (cpufreq_driver_resolve_freq(policy, freq) >= sg_policy->sag_freq_floor_khz)
			sg_cpu->util = swelt_u;
	}
}

/**
 * swelt_iowait_reset() - Reset the IO boost status of a CPU.
 * @sg_cpu: the swelt data for the CPU to boost
 * @time: the update time from the caller
 * @set_iowait_boost: true if an IO boost has been requested
 *
 * The IO wait boost of a task is disabled after a tick since the last update
 * of a CPU. If a new IO wait boost is requested after more then a tick, then
 * we enable the boost starting from IOWAIT_BOOST_MIN, which improves energy
 * efficiency by ignoring sporadic wakeups from IO.
 */
static bool swelt_iowait_reset(struct swelt_cpu *sg_cpu, u64 time,
			       bool set_iowait_boost)
{
	s64 delta_ns = time - sg_cpu->last_update;

	/* Reset boost only if a tick has elapsed since last request */
	if (delta_ns <= TICK_NSEC)
		return false;

	sg_cpu->iowait_boost = set_iowait_boost ? IOWAIT_BOOST_MIN : 0;
	sg_cpu->iowait_boost_pending = set_iowait_boost;

	return true;
}

/**
 * swelt_iowait_boost() - Updates the IO boost status of a CPU.
 * @sg_cpu: the swelt data for the CPU to boost
 * @time: the update time from the caller
 * @flags: SCHED_CPUFREQ_IOWAIT if the task is waking up after an IO wait
 *
 * Each time a task wakes up after an IO operation, the CPU utilization can be
 * boosted to a certain utilization which doubles at each "frequent and
 * successive" wakeup from IO, ranging from IOWAIT_BOOST_MIN to the utilization
 * of the maximum OPP.
 *
 * To keep doubling, an IO boost has to be requested at least once per tick,
 * otherwise we restart from the utilization of the minimum OPP.
 */
static void swelt_iowait_boost(struct swelt_cpu *sg_cpu, u64 time,
			       unsigned int flags)
{
	bool set_iowait_boost = flags & SCHED_CPUFREQ_IOWAIT;

	/* Reset boost if the CPU appears to have been idle enough */
	if (sg_cpu->iowait_boost &&
	    swelt_iowait_reset(sg_cpu, time, set_iowait_boost))
		return;

	/* Boost only tasks waking up after IO */
	if (!set_iowait_boost)
		return;

	/* Ensure boost doubles only one time at each request */
	if (sg_cpu->iowait_boost_pending)
		return;
	sg_cpu->iowait_boost_pending = true;

	/* Double the boost at each request */
	if (sg_cpu->iowait_boost) {
		sg_cpu->iowait_boost =
			min_t(unsigned int, sg_cpu->iowait_boost << 1,
			      SCHED_CAPACITY_SCALE);
		return;
	}

	/* First wakeup after IO: start with minimum boost */
	sg_cpu->iowait_boost = IOWAIT_BOOST_MIN;
}

/**
 * swelt_iowait_apply() - Apply the IO boost to a CPU.
 * @sg_cpu: the swelt data for the cpu to boost
 * @time: the update time from the caller
 *
 * A CPU running a task which woken up after an IO operation can have its
 * utilization boosted to speed up the completion of those IO operations.
 * The IO boost value is increased each time a task wakes up from IO, in
 * swelt_iowait_apply(), and it's instead decreased by this function,
 * each time an increase has not been requested (!iowait_boost_pending).
 *
 * A CPU which also appears to have been idle for at least one tick has also
 * its IO boost utilization reset.
 *
 * This mechanism is designed to boost high frequently IO waiting tasks, while
 * being more conservative on tasks which does sporadic IO operations.
 */
static void swelt_iowait_apply(struct swelt_cpu *sg_cpu, u64 time)
{
	unsigned long boost;

	/* No boost currently required */
	if (!sg_cpu->iowait_boost)
		return;

	/* Reset boost if the CPU appears to have been idle enough */
	if (swelt_iowait_reset(sg_cpu, time, false))
		return;

	if (!sg_cpu->iowait_boost_pending) {
		/*
		 * No boost pending; reduce the boost value.
		 */
		sg_cpu->iowait_boost >>= 1;
		if (sg_cpu->iowait_boost < IOWAIT_BOOST_MIN) {
			sg_cpu->iowait_boost = 0;
			return;
		}
	}

	sg_cpu->iowait_boost_pending = false;

	/*
	 * sg_cpu->util is already in capacity scale; convert iowait_boost
	 * into the same scale so we can compare.
	 */
	boost = (sg_cpu->iowait_boost * sg_cpu->max) >> SCHED_CAPACITY_SHIFT;
	boost = uclamp_rq_util_with(cpu_rq(sg_cpu->cpu), boost, NULL);
	if (sg_cpu->util < boost)
		sg_cpu->util = boost;
}

#ifdef CONFIG_NO_HZ_COMMON
static bool swelt_cpu_is_busy(struct swelt_cpu *sg_cpu)
{
	unsigned long idle_calls = tick_nohz_get_idle_calls_cpu(sg_cpu->cpu);
	bool ret = idle_calls == sg_cpu->saved_idle_calls;

	sg_cpu->saved_idle_calls = idle_calls;
	return ret;
}
#else
static inline bool swelt_cpu_is_busy(struct swelt_cpu *sg_cpu) { return false; }
#endif /* CONFIG_NO_HZ_COMMON */

/*
 * Make swelt_should_update_freq() ignore the rate limit when DL
 * has increased the utilization.
 */
static inline void ignore_dl_rate_limit(struct swelt_cpu *sg_cpu)
{
	if (cpu_bw_dl(cpu_rq(sg_cpu->cpu)) > sg_cpu->bw_dl)
		sg_cpu->sg_policy->limits_changed = true;
}

static inline bool swelt_update_single_common(struct swelt_cpu *sg_cpu,
					      u64 time, unsigned int flags)
{
	swelt_iowait_boost(sg_cpu, time, flags);
	sg_cpu->last_update = time;

	ignore_dl_rate_limit(sg_cpu);

	if (!swelt_should_update_freq(sg_cpu->sg_policy, time))
		return false;

	swelt_get_util(sg_cpu);
	swelt_iowait_apply(sg_cpu, time);

	return true;
}

static void swelt_update_single_freq(struct update_util_data *hook, u64 time,
				     unsigned int flags)
{
	struct swelt_cpu *sg_cpu = container_of(hook, struct swelt_cpu, update_util);
	struct swelt_policy *sg_policy = sg_cpu->sg_policy;
	unsigned int cached_freq = sg_policy->cached_raw_freq;
	unsigned int next_f;

	if (!swelt_update_single_common(sg_cpu, time, flags))
		return;

	next_f = get_next_freq(sg_policy, sg_cpu->util, sg_cpu->max);
	/*
	 * Do not reduce the frequency if the CPU has not been idle
	 * recently, as the reduction is likely to be premature then.
	 *
	 * Except when the rq is capped by uclamp_max.
	 */
	if (!uclamp_rq_is_capped(cpu_rq(sg_cpu->cpu)) &&
	    swelt_cpu_is_busy(sg_cpu) && next_f < sg_policy->next_freq &&
	    !sg_policy->need_freq_update) {
		next_f = sg_policy->next_freq;

		/* Restore cached freq as next_freq has changed */
		sg_policy->cached_raw_freq = cached_freq;
	}

	if (!swelt_update_next_freq(sg_policy, time, next_f))
		return;

	/*
	 * This code runs under rq->lock for the target CPU, so it won't run
	 * concurrently on two different CPUs for the same target and it is not
	 * necessary to acquire the lock in the fast switch case.
	 */
	if (sg_policy->policy->fast_switch_enabled) {
		cpufreq_driver_fast_switch(sg_policy->policy, next_f);
	} else {
		raw_spin_lock(&sg_policy->update_lock);
		swelt_deferred_update(sg_policy);
		raw_spin_unlock(&sg_policy->update_lock);
	}
}

static void swelt_update_single_perf(struct update_util_data *hook, u64 time,
				     unsigned int flags)
{
	struct swelt_cpu *sg_cpu = container_of(hook, struct swelt_cpu, update_util);
	unsigned long prev_util = sg_cpu->util;

	/*
	 * Fall back to the "frequency" path if frequency invariance is not
	 * supported, because the direct mapping between the utilization and
	 * the performance levels depends on the frequency invariance.
	 */
	if (!arch_scale_freq_invariant()) {
		swelt_update_single_freq(hook, time, flags);
		return;
	}

	if (!swelt_update_single_common(sg_cpu, time, flags))
		return;

	/*
	 * Do not reduce the target performance level if the CPU has not been
	 * idle recently, as the reduction is likely to be premature then.
	 *
	 * Except when the rq is capped by uclamp_max.
	 */
	if (!uclamp_rq_is_capped(cpu_rq(sg_cpu->cpu)) &&
	    swelt_cpu_is_busy(sg_cpu) && sg_cpu->util < prev_util)
		sg_cpu->util = prev_util;

	cpufreq_driver_adjust_perf(sg_cpu->cpu, map_util_perf(sg_cpu->bw_dl),
				   map_util_perf(sg_cpu->util), sg_cpu->max);

	sg_cpu->sg_policy->last_freq_update_time = time;
}

static unsigned int swelt_next_freq_shared(struct swelt_cpu *sg_cpu, u64 time)
{
	struct swelt_policy *sg_policy = sg_cpu->sg_policy;
	struct cpufreq_policy *policy = sg_policy->policy;
	unsigned long util = 0, max = 1;
	unsigned int j;

	for_each_cpu(j, policy->cpus) {
		struct swelt_cpu *j_sg_cpu = &per_cpu(swelt_cpu, j);
		unsigned long j_util, j_max;

		swelt_get_util(j_sg_cpu);
		swelt_iowait_apply(j_sg_cpu, time);
		j_util = j_sg_cpu->util;
		j_max  = j_sg_cpu->max;

		if (j_util * max > j_max * util) {
			util = j_util;
			max  = j_max;
		}
	}

	return get_next_freq(sg_policy, util, max);
}

static void
swelt_update_shared(struct update_util_data *hook, u64 time, unsigned int flags)
{
	struct swelt_cpu *sg_cpu = container_of(hook, struct swelt_cpu, update_util);
	struct swelt_policy *sg_policy = sg_cpu->sg_policy;
	unsigned int next_f;
	bool sag_active = false;

	raw_spin_lock(&sg_policy->update_lock);

	swelt_iowait_boost(sg_cpu, time, flags);
	sg_cpu->last_update = time;

	ignore_dl_rate_limit(sg_cpu);

#ifdef CONFIG_CGROUP_SCHED
	sag_active = sg_policy->sag_boost_enabled &&
		     rq_has_topapp_running(cpu_rq(sg_cpu->cpu));
#endif

	if (swelt_should_update_freq(sg_policy, time) || sag_active) {

#ifdef CONFIG_CGROUP_SCHED
		/*
		 * SAG: scale util upward when a ui_critical task is running.
		 * sag_util_clamp_pct=100 is a no-op; >100 adds headroom.
		 */
		if (sag_active && sg_policy->sag_util_clamp_pct != 100) {
			sg_cpu->util = sg_cpu->util *
				       sg_policy->sag_util_clamp_pct / 100;
			sg_cpu->util = min(sg_cpu->util, sg_cpu->max);
		}
#endif

		next_f = swelt_next_freq_shared(sg_cpu, time);

#ifdef CONFIG_CGROUP_SCHED
		/* SAG: frequency floor for ui_critical tasks */
		if (sag_active && sg_policy->sag_freq_min_khz)
			next_f = max(next_f, sg_policy->sag_freq_min_khz);

		/*
		 * SAG: ramp-UP rate-limit bypass for ui_critical tasks.
		 *
		 * sag_up_freq_update_delay_ns == 0  → full bypass (zero the
		 *   last_freq_update_time so swelt_update_next_freq() always
		 *   passes the up-delay check).
		 * sag_up_freq_update_delay_ns  > 0  → use a shorter, SAG-
		 *   specific up rate-limit instead of the global one.
		 *
		 * Preserving the down rate-limit prevents frequency from
		 * collapsing between the vsync wakeup and GPU submit.
		 */
		if (sag_active && next_f > sg_policy->next_freq) {
			if (sg_policy->sag_up_freq_update_delay_ns == 0) {
				sg_policy->last_freq_update_time = 0;
			} else {
				s64 delta_ns = time -
					sg_policy->last_freq_update_time;
				if (delta_ns < sg_policy->sag_up_freq_update_delay_ns)
					goto unlock;
			}
		}
#endif

		if (!swelt_update_next_freq(sg_policy, time, next_f))
			goto unlock;

		if (sg_policy->policy->fast_switch_enabled)
			cpufreq_driver_fast_switch(sg_policy->policy, next_f);
		else
			swelt_deferred_update(sg_policy);
	}
unlock:
	raw_spin_unlock(&sg_policy->update_lock);
}

static void swelt_work(struct kthread_work *work)
{
	struct swelt_policy *sg_policy = container_of(work, struct swelt_policy, work);
	unsigned int freq;
	unsigned long flags;

	/*
	 * Hold sg_policy->update_lock shortly to handle the case where:
	 * in case sg_policy->next_freq is read here, and then updated by
	 * swelt_deferred_update() just before work_in_progress is set to false
	 * here, we may miss queueing the new update.
	 *
	 * Note: If a work was queued after the update_lock is released,
	 * swelt_work() will just be called again by kthread_work code; and the
	 * request will be proceed before the swelt thread sleeps.
	 */
	raw_spin_lock_irqsave(&sg_policy->update_lock, flags);
	freq = sg_policy->next_freq;
	sg_policy->work_in_progress = false;
	raw_spin_unlock_irqrestore(&sg_policy->update_lock, flags);

	mutex_lock(&sg_policy->work_lock);
	__cpufreq_driver_target(sg_policy->policy, freq, CPUFREQ_RELATION_L);
	mutex_unlock(&sg_policy->work_lock);
}

static void swelt_irq_work(struct irq_work *irq_work)
{
	struct swelt_policy *sg_policy;

	sg_policy = container_of(irq_work, struct swelt_policy, irq_work);

	kthread_queue_work(&sg_policy->worker, &sg_policy->work);
}

/************************** sysfs interface ************************/

static DEFINE_MUTEX(min_rate_lock);

static void update_min_rate_limit_ns(struct swelt_policy *sg_policy)
{
	mutex_lock(&min_rate_lock);
	sg_policy->min_rate_limit_ns = min(sg_policy->up_freq_update_delay_ns,
					   sg_policy->down_freq_update_delay_ns);
	mutex_unlock(&min_rate_lock);
}

static struct swelt_tunables *global_tunables;
static DEFINE_MUTEX(global_tunables_lock);

static inline struct swelt_tunables *to_swelt_tunables(struct gov_attr_set *attr_set)
{
	return container_of(attr_set, struct swelt_tunables, attr_set);
}

/* up_rate_limit_us */
static ssize_t up_rate_limit_us_show(struct gov_attr_set *attr_set, char *buf)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);

	return sprintf(buf, "%u\n", tunables->up_rate_limit_us);
}

static ssize_t
up_rate_limit_us_store(struct gov_attr_set *attr_set, const char *buf,
		       size_t count)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);
	struct swelt_policy *sg_policy;
	unsigned int up_rate_limit_us;

	if (kstrtouint(buf, 10, &up_rate_limit_us))
		return -EINVAL;

	tunables->up_rate_limit_us = up_rate_limit_us;

	list_for_each_entry(sg_policy, &attr_set->policy_list, tunables_hook)
		sg_policy->up_freq_update_delay_ns =
			up_rate_limit_us * NSEC_PER_USEC;

	return count;
}
static struct governor_attr up_rate_limit_us = __ATTR_RW(up_rate_limit_us);

/* down_rate_limit_us */
static ssize_t down_rate_limit_us_show(struct gov_attr_set *attr_set, char *buf)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);

	return sprintf(buf, "%u\n", tunables->down_rate_limit_us);
}

static ssize_t
down_rate_limit_us_store(struct gov_attr_set *attr_set, const char *buf,
			 size_t count)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);
	struct swelt_policy *sg_policy;
	unsigned int down_rate_limit_us;

	if (kstrtouint(buf, 10, &down_rate_limit_us))
		return -EINVAL;

	tunables->down_rate_limit_us = down_rate_limit_us;

	list_for_each_entry(sg_policy, &attr_set->policy_list, tunables_hook)
		sg_policy->down_freq_update_delay_ns =
			down_rate_limit_us * NSEC_PER_USEC;

	return count;
}
static struct governor_attr down_rate_limit_us = __ATTR_RW(down_rate_limit_us);

/* -----------------------------------------------------------------
 * SAG: window-max filter tunables
 * ----------------------------------------------------------------- */

/* sag_filter_enabled */
static ssize_t sag_filter_enabled_show(struct gov_attr_set *attr_set, char *buf)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);

	return sprintf(buf, "%d\n", tunables->sag_filter_enabled);
}

static ssize_t sag_filter_enabled_store(struct gov_attr_set *attr_set,
					const char *buf, size_t count)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);
	struct swelt_policy *sg_policy;
	unsigned int val;

	if (kstrtouint(buf, 10, &val) || val > 1)
		return -EINVAL;

	tunables->sag_filter_enabled = (bool)val;

	list_for_each_entry(sg_policy, &attr_set->policy_list, tunables_hook)
		sg_policy->sag_filter_enabled = tunables->sag_filter_enabled;

	return count;
}
static struct governor_attr sag_filter_enabled = __ATTR_RW(sag_filter_enabled);

/* sag_windows */
static ssize_t sag_windows_show(struct gov_attr_set *attr_set, char *buf)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);

	return sprintf(buf, "%u\n", tunables->sag_windows);
}

static ssize_t sag_windows_store(struct gov_attr_set *attr_set,
				 const char *buf, size_t count)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);
	struct swelt_policy *sg_policy;
	unsigned int val;

	/* Cap to static array size to avoid out-of-bounds history access */
	if (kstrtouint(buf, 10, &val) || val == 0 || val > SWELT_WINDOWS)
		return -EINVAL;

	tunables->sag_windows = val;

	list_for_each_entry(sg_policy, &attr_set->policy_list, tunables_hook)
		sg_policy->sag_windows = val;

	return count;
}
static struct governor_attr sag_windows = __ATTR_RW(sag_windows);

/* sag_window_duration_us */
static ssize_t sag_window_duration_us_show(struct gov_attr_set *attr_set,
					   char *buf)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);

	return sprintf(buf, "%u\n", tunables->sag_window_duration_us);
}

static ssize_t sag_window_duration_us_store(struct gov_attr_set *attr_set,
					    const char *buf, size_t count)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);
	struct swelt_policy *sg_policy;
	unsigned int val;

	/* Sanity: at least 1 ms, at most 100 ms */
	if (kstrtouint(buf, 10, &val) || val < 1000 || val > 100000)
		return -EINVAL;

	tunables->sag_window_duration_us = val;

	list_for_each_entry(sg_policy, &attr_set->policy_list, tunables_hook)
		sg_policy->sag_window_duration_us = val;

	return count;
}
static struct governor_attr sag_window_duration_us =
	__ATTR_RW(sag_window_duration_us);

/* sag_freq_floor_khz */
static ssize_t sag_freq_floor_khz_show(struct gov_attr_set *attr_set, char *buf)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);

	return sprintf(buf, "%u\n", tunables->sag_freq_floor_khz);
}

static ssize_t sag_freq_floor_khz_store(struct gov_attr_set *attr_set,
					const char *buf, size_t count)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);
	struct swelt_policy *sg_policy;
	unsigned int val;

	if (kstrtouint(buf, 10, &val))
		return -EINVAL;

	tunables->sag_freq_floor_khz = val;

	list_for_each_entry(sg_policy, &attr_set->policy_list, tunables_hook)
		sg_policy->sag_freq_floor_khz = val;

	return count;
}
static struct governor_attr sag_freq_floor_khz = __ATTR_RW(sag_freq_floor_khz);

/* sag_filter_max_cpu */
static ssize_t sag_filter_max_cpu_show(struct gov_attr_set *attr_set, char *buf)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);

	return sprintf(buf, "%u\n", tunables->sag_filter_max_cpu);
}

static ssize_t sag_filter_max_cpu_store(struct gov_attr_set *attr_set,
					 const char *buf, size_t count)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);
	struct swelt_policy *sg_policy;
	unsigned int val;

	if (kstrtouint(buf, 10, &val) || val >= nr_cpu_ids)
		return -EINVAL;

	tunables->sag_filter_max_cpu = val;

	list_for_each_entry(sg_policy, &attr_set->policy_list, tunables_hook)
		sg_policy->sag_filter_max_cpu = val;

	return count;
}
static struct governor_attr sag_filter_max_cpu = __ATTR_RW(sag_filter_max_cpu);

#ifdef CONFIG_CGROUP_SCHED
/* -----------------------------------------------------------------
 * SAG: scheduler-assisted boost tunables (ui_critical path)
 * ----------------------------------------------------------------- */

/* sag_boost_enabled */
static ssize_t sag_boost_enabled_show(struct gov_attr_set *attr_set, char *buf)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);

	return sprintf(buf, "%d\n", tunables->sag_boost_enabled);
}

static ssize_t sag_boost_enabled_store(struct gov_attr_set *attr_set,
					const char *buf, size_t count)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);
	struct swelt_policy *sg_policy;
	unsigned int val;

	if (kstrtouint(buf, 10, &val) || val > 1)
		return -EINVAL;

	tunables->sag_boost_enabled = (bool)val;

	list_for_each_entry(sg_policy, &attr_set->policy_list, tunables_hook)
		sg_policy->sag_boost_enabled = tunables->sag_boost_enabled;

	return count;
}
static struct governor_attr sag_boost_enabled = __ATTR_RW(sag_boost_enabled);

/* sag_up_rate_limit_us */
static ssize_t sag_up_rate_limit_us_show(struct gov_attr_set *attr_set,
					 char *buf)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);

	return sprintf(buf, "%u\n", tunables->sag_up_rate_limit_us);
}

static ssize_t sag_up_rate_limit_us_store(struct gov_attr_set *attr_set,
					  const char *buf, size_t count)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);
	struct swelt_policy *sg_policy;
	unsigned int val;

	if (kstrtouint(buf, 10, &val))
		return -EINVAL;

	tunables->sag_up_rate_limit_us = val;

	list_for_each_entry(sg_policy, &attr_set->policy_list, tunables_hook)
		sg_policy->sag_up_freq_update_delay_ns =
			(s64)val * NSEC_PER_USEC;

	return count;
}
static struct governor_attr sag_up_rate_limit_us =
	__ATTR_RW(sag_up_rate_limit_us);

/* sag_freq_min_khz */
static ssize_t sag_freq_min_khz_show(struct gov_attr_set *attr_set, char *buf)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);

	return sprintf(buf, "%u\n", tunables->sag_freq_min_khz);
}

static ssize_t sag_freq_min_khz_store(struct gov_attr_set *attr_set,
				      const char *buf, size_t count)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);
	struct swelt_policy *sg_policy;
	unsigned int val;

	if (kstrtouint(buf, 10, &val))
		return -EINVAL;

	tunables->sag_freq_min_khz = val;

	list_for_each_entry(sg_policy, &attr_set->policy_list, tunables_hook)
		sg_policy->sag_freq_min_khz = val;

	return count;
}
static struct governor_attr sag_freq_min_khz = __ATTR_RW(sag_freq_min_khz);

/* sag_util_clamp_pct */
static ssize_t sag_util_clamp_pct_show(struct gov_attr_set *attr_set, char *buf)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);

	return sprintf(buf, "%u\n", tunables->sag_util_clamp_pct);
}

static ssize_t sag_util_clamp_pct_store(struct gov_attr_set *attr_set,
					const char *buf, size_t count)
{
	struct swelt_tunables *tunables = to_swelt_tunables(attr_set);
	struct swelt_policy *sg_policy;
	unsigned int val;

	/* 50–200% is a reasonable guard range */
	if (kstrtouint(buf, 10, &val) || val < 50 || val > 200)
		return -EINVAL;

	tunables->sag_util_clamp_pct = val;

	list_for_each_entry(sg_policy, &attr_set->policy_list, tunables_hook)
		sg_policy->sag_util_clamp_pct = val;

	return count;
}
static struct governor_attr sag_util_clamp_pct =
	__ATTR_RW(sag_util_clamp_pct);
#endif /* CONFIG_CGROUP_SCHED */

static struct attribute *swelt_attrs[] = {
	&up_rate_limit_us.attr,
	&down_rate_limit_us.attr,
	/* SAG: filter */
	&sag_filter_enabled.attr,
	&sag_windows.attr,
	&sag_window_duration_us.attr,
	&sag_freq_floor_khz.attr,
	&sag_filter_max_cpu.attr,
#ifdef CONFIG_CGROUP_SCHED
	/* SAG: boost */
	&sag_boost_enabled.attr,
	&sag_up_rate_limit_us.attr,
	&sag_freq_min_khz.attr,
	&sag_util_clamp_pct.attr,
#endif
	NULL
};
ATTRIBUTE_GROUPS(swelt);

static void swelt_tunables_free(struct kobject *kobj)
{
	struct gov_attr_set *attr_set = to_gov_attr_set(kobj);

	kfree(to_swelt_tunables(attr_set));
}

static struct kobj_type swelt_tunables_ktype = {
	.default_groups = swelt_groups,
	.sysfs_ops	= &governor_sysfs_ops,
	.release	= &swelt_tunables_free,
};

/********************** cpufreq governor interface *********************/

struct cpufreq_governor swelt_gov;

static struct swelt_policy *swelt_policy_alloc(struct cpufreq_policy *policy)
{
	struct swelt_policy *sg_policy;

	sg_policy = kzalloc(sizeof(*sg_policy), GFP_KERNEL);
	if (!sg_policy)
		return NULL;

	sg_policy->policy = policy;
	raw_spin_lock_init(&sg_policy->update_lock);
	return sg_policy;
}

static void swelt_policy_free(struct swelt_policy *sg_policy)
{
	kfree(sg_policy);
}

static int swelt_kthread_create(struct swelt_policy *sg_policy)
{
	struct task_struct *thread;
	struct sched_attr attr = {
		.size		= sizeof(struct sched_attr),
		.sched_policy	= SCHED_DEADLINE,
		.sched_flags	= SCHED_FLAG_SUGOV,
		.sched_nice	= 0,
		.sched_priority	= 0,
		/*
		 * Fake (unused) bandwidth; workaround to "fix"
		 * priority inheritance.
		 */
		.sched_runtime	=  1000000,
		.sched_deadline = 10000000,
		.sched_period	= 10000000,
	};
	struct cpufreq_policy *policy = sg_policy->policy;
	int ret;

	/* kthread only required for slow path */
	if (policy->fast_switch_enabled)
		return 0;

	kthread_init_work(&sg_policy->work, swelt_work);
	kthread_init_worker(&sg_policy->worker);
	thread = kthread_create(kthread_worker_fn, &sg_policy->worker,
				"swelt:%d",
				cpumask_first(policy->related_cpus));
	if (IS_ERR(thread)) {
		pr_err("failed to create swelt thread: %ld\n", PTR_ERR(thread));
		return PTR_ERR(thread);
	}

	ret = sched_setattr_nocheck(thread, &attr);
	if (ret) {
		kthread_stop(thread);
		pr_warn("%s: failed to set SCHED_DEADLINE\n", __func__);
		return ret;
	}

	sg_policy->thread = thread;
	kthread_bind_mask(thread, policy->related_cpus);
	init_irq_work(&sg_policy->irq_work, swelt_irq_work);
	mutex_init(&sg_policy->work_lock);

	wake_up_process(thread);

	return 0;
}

static void swelt_kthread_stop(struct swelt_policy *sg_policy)
{
	/* kthread only required for slow path */
	if (sg_policy->policy->fast_switch_enabled)
		return;

	kthread_flush_worker(&sg_policy->worker);
	kthread_stop(sg_policy->thread);
	mutex_destroy(&sg_policy->work_lock);
}

static struct swelt_tunables *swelt_tunables_alloc(struct swelt_policy *sg_policy)
{
	struct swelt_tunables *tunables;

	tunables = kzalloc(sizeof(*tunables), GFP_KERNEL);
	if (tunables) {
		gov_attr_set_init(&tunables->attr_set, &sg_policy->tunables_hook);
		if (!have_governor_per_policy())
			global_tunables = tunables;
	}
	return tunables;
}

static void swelt_clear_global_tunables(void)
{
	if (!have_governor_per_policy())
		global_tunables = NULL;
}

static int swelt_init(struct cpufreq_policy *policy)
{
	struct swelt_policy *sg_policy;
	struct swelt_tunables *tunables;
	int ret = 0;

	/* State should be equivalent to EXIT */
	if (policy->governor_data)
		return -EBUSY;

	cpufreq_enable_fast_switch(policy);

	sg_policy = swelt_policy_alloc(policy);
	if (!sg_policy) {
		ret = -ENOMEM;
		goto disable_fast_switch;
	}

	ret = swelt_kthread_create(sg_policy);
	if (ret)
		goto free_sg_policy;

	mutex_lock(&global_tunables_lock);

	if (global_tunables) {
		if (WARN_ON(have_governor_per_policy())) {
			ret = -EINVAL;
			goto stop_kthread;
		}
		policy->governor_data = sg_policy;
		sg_policy->tunables = global_tunables;

		gov_attr_set_get(&global_tunables->attr_set,
				 &sg_policy->tunables_hook);
		goto out;
	}

	tunables = swelt_tunables_alloc(sg_policy);
	if (!tunables) {
		ret = -ENOMEM;
		goto stop_kthread;
	}

	/* existing rate limits */
	tunables->up_rate_limit_us   = 0;
	tunables->down_rate_limit_us = 0;

	/* SAG: filter defaults */
	tunables->sag_filter_enabled     = true;
	tunables->sag_windows            = SWELT_WINDOWS;
	tunables->sag_window_duration_us = SWELT_WINDOW_NS / NSEC_PER_USEC;
	tunables->sag_freq_floor_khz     = 1478000;
	tunables->sag_filter_max_cpu     = SWELT_FILTER_MAX_CPU;

#ifdef CONFIG_CGROUP_SCHED
	/* SAG: boost defaults */
	tunables->sag_boost_enabled   = true;
	tunables->sag_up_rate_limit_us = 0;    /* full bypass */
	tunables->sag_freq_min_khz    = 0;     /* disabled    */
	tunables->sag_util_clamp_pct  = 100;   /* no scaling  */
#endif

	policy->governor_data = sg_policy;
	sg_policy->tunables   = tunables;

	ret = kobject_init_and_add(&tunables->attr_set.kobj,
				   &swelt_tunables_ktype,
				   get_governor_parent_kobj(policy), "%s",
				   swelt_gov.name);
	if (ret)
		goto fail;

out:
	mutex_unlock(&global_tunables_lock);
	return 0;

fail:
	kobject_put(&tunables->attr_set.kobj);
	policy->governor_data = NULL;
	swelt_clear_global_tunables();

stop_kthread:
	swelt_kthread_stop(sg_policy);
	mutex_unlock(&global_tunables_lock);

free_sg_policy:
	swelt_policy_free(sg_policy);

disable_fast_switch:
	cpufreq_disable_fast_switch(policy);

	pr_err("initialization failed (error %d)\n", ret);
	return ret;
}

static void swelt_exit(struct cpufreq_policy *policy)
{
	struct swelt_policy *sg_policy = policy->governor_data;
	struct swelt_tunables *tunables = sg_policy->tunables;
	unsigned int count;

	mutex_lock(&global_tunables_lock);

	count = gov_attr_set_put(&tunables->attr_set, &sg_policy->tunables_hook);
	policy->governor_data = NULL;
	if (!count)
		swelt_clear_global_tunables();

	mutex_unlock(&global_tunables_lock);

	swelt_kthread_stop(sg_policy);
	swelt_policy_free(sg_policy);
	cpufreq_disable_fast_switch(policy);
}

static int swelt_start(struct cpufreq_policy *policy)
{
	struct swelt_policy *sg_policy = policy->governor_data;
	struct swelt_tunables *tunables = sg_policy->tunables;
	void (*uu)(struct update_util_data *data, u64 time, unsigned int flags);
	unsigned int cpu;

	/* existing */
	sg_policy->up_freq_update_delay_ns   = tunables->up_rate_limit_us *
						NSEC_PER_USEC;
	sg_policy->down_freq_update_delay_ns = tunables->down_rate_limit_us *
						NSEC_PER_USEC;
	update_min_rate_limit_ns(sg_policy);
	sg_policy->last_freq_update_time  = 0;
	sg_policy->next_freq              = 0;
	sg_policy->work_in_progress       = false;
	sg_policy->limits_changed         = false;
	sg_policy->cached_raw_freq        = 0;

	sg_policy->need_freq_update =
		cpufreq_driver_test_flags(CPUFREQ_NEED_UPDATE_LIMITS);

	/* SAG: mirror filter tunables onto policy for lock-free hot-path reads */
	sg_policy->sag_filter_enabled     = tunables->sag_filter_enabled;
	sg_policy->sag_windows            = tunables->sag_windows;
	sg_policy->sag_window_duration_us = tunables->sag_window_duration_us;
	sg_policy->sag_freq_floor_khz     = tunables->sag_freq_floor_khz;
	sg_policy->sag_filter_max_cpu     = tunables->sag_filter_max_cpu;

#ifdef CONFIG_CGROUP_SCHED
	/* SAG: mirror boost tunables */
	sg_policy->sag_boost_enabled           = tunables->sag_boost_enabled;
	sg_policy->sag_up_freq_update_delay_ns =
		(s64)tunables->sag_up_rate_limit_us * NSEC_PER_USEC;
	sg_policy->sag_freq_min_khz            = tunables->sag_freq_min_khz;
	sg_policy->sag_util_clamp_pct          = tunables->sag_util_clamp_pct;
#endif

	for_each_cpu(cpu, policy->cpus) {
		struct swelt_cpu *sg_cpu = &per_cpu(swelt_cpu, cpu);

		memset(sg_cpu, 0, sizeof(*sg_cpu));
		sg_cpu->cpu       = cpu;
		sg_cpu->sg_policy = sg_policy;
	}

	if (policy_is_shared(policy))
		uu = swelt_update_shared;
	else if (policy->fast_switch_enabled && cpufreq_driver_has_adjust_perf())
		uu = swelt_update_single_perf;
	else
		uu = swelt_update_single_freq;

	for_each_cpu(cpu, policy->cpus) {
		struct swelt_cpu *sg_cpu = &per_cpu(swelt_cpu, cpu);

		cpufreq_add_update_util_hook(cpu, &sg_cpu->update_util, uu);
	}
	return 0;
}

static void swelt_stop(struct cpufreq_policy *policy)
{
	struct swelt_policy *sg_policy = policy->governor_data;
	unsigned int cpu;

	for_each_cpu(cpu, policy->cpus)
		cpufreq_remove_update_util_hook(cpu);

	synchronize_rcu();

	if (!policy->fast_switch_enabled) {
		irq_work_sync(&sg_policy->irq_work);
		kthread_cancel_work_sync(&sg_policy->work);
	}
}

static void swelt_limits(struct cpufreq_policy *policy)
{
	struct swelt_policy *sg_policy = policy->governor_data;

	if (!policy->fast_switch_enabled) {
		mutex_lock(&sg_policy->work_lock);
		cpufreq_policy_apply_limits(policy);
		mutex_unlock(&sg_policy->work_lock);
	}

	sg_policy->limits_changed = true;
}

struct cpufreq_governor swelt_gov = {
	.name		= "swelt",
	.owner		= THIS_MODULE,
	.flags		= CPUFREQ_GOV_DYNAMIC_SWITCHING,
	.init		= swelt_init,
	.exit		= swelt_exit,
	.start		= swelt_start,
	.stop		= swelt_stop,
	.limits		= swelt_limits,
};

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_SWELT
struct cpufreq_governor *cpufreq_default_governor(void)
{
	return &swelt_gov;
}
#endif

cpufreq_governor_init(swelt_gov);