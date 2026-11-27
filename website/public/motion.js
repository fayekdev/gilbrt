// Content remains visible if animations or IntersectionObserver are unavailable.
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
const running = new Set();
function reveal(element, delay = 0) {
  if (reducedMotion.matches) return;
  const animation = element.animate([
    { opacity: 0, transform: 'translateY(16px)' },
    { opacity: 1, transform: 'translateY(0)' },
  ], { duration: 650, delay, easing: 'cubic-bezier(.16,1,.3,1)', fill: 'backwards' });
  running.add(animation);
  animation.finished.then(() => running.delete(animation), () => running.delete(animation));
}
[...document.querySelectorAll('.hero-copy > *')].forEach((element, index) => reveal(element, index * 65));
if ('IntersectionObserver' in window) {
  const observer = new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      reveal(entry.target);
      observer.unobserve(entry.target);
    }
  }, { threshold: .08 });
  document.querySelectorAll('[data-reveal]').forEach(element => observer.observe(element));
}
reducedMotion.addEventListener('change', () => {
  if (reducedMotion.matches) for (const animation of running) animation.cancel();
});
