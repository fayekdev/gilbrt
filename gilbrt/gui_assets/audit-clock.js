/* Pure elapsed-time calculations shared by the live audit popup and its tests. */
'use strict';
globalThis.GilbrtAuditClock = Object.freeze({
  seconds(sample, now) {
    if (!sample) return 0;
    return sample.seconds + (sample.active ? Math.max(0, now - sample.at) / 1000 : 0);
  },
  sample(job, previous, now) {
    if (!job) return null;
    const active = ['running', 'cancelling'].includes(job.status);
    const value = Number(job.elapsed);
    let seconds = Number.isFinite(value) ? Math.max(0, value) : 0;
    if (active && previous?.id === job.id) seconds = Math.max(seconds, this.seconds(previous, now));
    return {id:job.id, seconds, at:now, active};
  },
  format(value) {
    const seconds = Number.isFinite(value) ? Math.floor(Math.max(0, value)) : 0;
    const hours = Math.floor(seconds / 3600), minutes = Math.floor(seconds / 60) % 60;
    const pad = number => String(number).padStart(2, '0');
    return (hours ? `${pad(hours)}:` : '') + `${pad(minutes)}:${pad(seconds % 60)}`;
  }
});
