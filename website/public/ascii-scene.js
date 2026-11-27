import * as THREE from './vendor/three/three.module.js';

const host = document.querySelector('#ascii-scene');
const pointerSurface = document.querySelector('.hero') || host;
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');

// Every visible source character becomes a glyph on a curved 3D surface.
// The source SVG remains the fallback when modules or WebGL are unavailable.
async function createScene() {
  const response = await fetch('/mascot-ascii.svg');
  if (!response.ok) throw new Error('ASCII source unavailable');
  const svg = new DOMParser().parseFromString(await response.text(), 'image/svg+xml');
  const rows = [...svg.querySelectorAll('text')];
  const alphabet = [...new Set(rows.flatMap(row => [...row.textContent]).filter(char => char !== ' '))];
  const cell = 64;
  const atlas = document.createElement('canvas');
  atlas.width = cell * alphabet.length;
  atlas.height = cell;
  const context = atlas.getContext('2d');
  context.fillStyle = '#fff';
  context.font = 'bold 42px "Courier New", monospace';
  context.textAlign = 'center';
  context.textBaseline = 'middle';
  alphabet.forEach((char, i) => context.fillText(char, cell * (i + .5), cell * .5));
  const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: false, powerPreference: 'low-power' });
  const texture = new THREE.CanvasTexture(atlas);
  texture.minFilter = THREE.LinearFilter;
  texture.magFilter = THREE.LinearFilter;
  texture.generateMipmaps = false;

  const positions = [];
  const glyphs = [];
  const colors = [];
  for (const row of rows) {
    const group = row.parentElement.getAttribute('class');
    const y = (320 - Number(row.getAttribute('y'))) / 100;
    const color = new THREE.Color(group === 'face' ? '#e7eee2' : group === 'body' || group === 'signal' ? '#afc29f' : '#8f9c8b').convertLinearToSRGB();
    [...row.textContent].forEach((char, index) => {
      if (char === ' ') return;
      const x = (16 + index * 8.4 - 369) / 100;
      const curve = Math.sqrt(Math.max(0, 1 - (x / 3.8) ** 2));
      const z = curve * .9 + Math.sin(y * .65) * .13 + (group === 'face' ? .32 : 0);
      positions.push(x, y, z);
      glyphs.push(alphabet.indexOf(char));
      colors.push(color.r, color.g, color.b);
    });
  }

  renderer.setClearColor(0x000000, 0);
  renderer.setPixelRatio(Math.min(devicePixelRatio, 1.5));
  renderer.domElement.setAttribute('aria-hidden', 'true');
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(35, 1, .1, 50);
  camera.position.z = 13.4;
  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
  geometry.setAttribute('glyph', new THREE.Float32BufferAttribute(glyphs, 1));
  geometry.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));
  const material = new THREE.ShaderMaterial({
    transparent: true,
    depthWrite: false,
    uniforms: { atlas: { value: texture }, glyphCount: { value: alphabet.length }, scale: { value: 1 }, time: { value: 0 }, motion: { value: reducedMotion.matches ? 0 : 1 }, reveal: { value: reducedMotion.matches ? 1 : 0 } },
    vertexShader: `
      attribute float glyph;
      attribute vec3 color;
      varying float vGlyph;
      varying vec3 vColor;
      uniform float scale;
      uniform float time;
      uniform float motion;
      uniform float reveal;
      varying float vHeight;
      void main() {
        vGlyph = glyph;
        vColor = color;
        vHeight = position.y;
        vec3 point = position;
        point.z += sin(position.y * 1.4 + time * .45) * .07 * motion;
        point.z += (1.0 - reveal) * sin(position.x * 13.0 + position.y * 4.0) * .65;
        vec4 positionInView = modelViewMatrix * vec4(point, 1.0);
        gl_Position = projectionMatrix * positionInView;
        gl_PointSize = .225 * scale / -positionInView.z;
      }
    `,
    fragmentShader: `
      uniform sampler2D atlas;
      uniform float glyphCount;
      uniform float time;
      uniform float motion;
      uniform float reveal;
      varying float vHeight;
      varying float vGlyph;
      varying vec3 vColor;
      void main() {
        vec2 uv = vec2((vGlyph + gl_PointCoord.x) / glyphCount, 1.0 - gl_PointCoord.y);
        float alpha = texture2D(atlas, uv).a;
        if (alpha < .03) discard;
        float sweep = exp(-pow((vHeight - mod(time * .55, 9.0) + 4.5) * 2.8, 2.0));
        vec3 shade = vColor * (1.0 + .65 * sweep * motion);
        gl_FragColor = vec4(shade, alpha * (.25 + .75 * reveal));
      }
    `,
  });
  const portrait = new THREE.Points(geometry, material);
  scene.add(portrait);
  let frame = 0;
  let lastRender = 0;
  let visible = true;
  let paused = reducedMotion.matches;
  let failed = false;
  let pointerX = 0;
  let pointerY = 0;
  let elapsed = 0;
  let lastTick = 0;

  function render() {
    renderer.render(scene, camera);
  }
  function resize() {
    const { width, height } = host.getBoundingClientRect();
    if (!width || !height || failed) return;
    renderer.setSize(width, height, false);
    camera.aspect = width / height;
    // Fit both portrait and narrow landscape containers without clipping.
    camera.position.z = Math.max(13.4, 12.8 / camera.aspect);
    camera.updateProjectionMatrix();
    material.uniforms.scale.value = height * renderer.getPixelRatio() / (2 * Math.tan(THREE.MathUtils.degToRad(17.5)));
    render();
  }
  function animate(time) {
    frame = 0;
    if (failed || paused || !visible || document.hidden) return;
    // This decorative scene does not need more than 30 frames per second.
    if (time - lastRender >= 32) {
      if (lastTick) elapsed += Math.min(time - lastTick, 64) / 1000;
      lastTick = time;
      material.uniforms.time.value = elapsed;
      material.uniforms.reveal.value = Math.min(1, elapsed / 1.15);
      portrait.position.y = Math.sin(elapsed * .45) * .035;
      const targetY = pointerX * .15 + Math.sin(time * .00022) * .075;
      const targetX = pointerY * -.07;
      portrait.rotation.y += (targetY - portrait.rotation.y) * .045;
      portrait.rotation.x += (targetX - portrait.rotation.x) * .045;
      render();
      lastRender = time;
    }
    frame = requestAnimationFrame(animate);
  }
  function syncMotion() {
    cancelAnimationFrame(frame);
    frame = 0;
    lastTick = 0;
    material.uniforms.motion.value = paused ? 0 : 1;
    if (!paused && visible && !document.hidden && !failed) frame = requestAnimationFrame(animate);
  }
  const onPointerMove = event => {
    if (paused || event.pointerType === 'touch') return;
    const rect = host.getBoundingClientRect();
    pointerX = Math.max(-1, Math.min(1, (event.clientX - rect.left) / rect.width * 2 - 1));
    pointerY = Math.max(-1, Math.min(1, (event.clientY - rect.top) / rect.height * 2 - 1));
  };
  const onPointerLeave = () => { pointerX = 0; pointerY = 0; };
  const onPreference = () => {
    paused = reducedMotion.matches;
    if (paused) { material.uniforms.motion.value = 0; material.uniforms.reveal.value = 1; portrait.rotation.set(0, 0, 0); portrait.position.y = 0; render(); }
    syncMotion();
  };
  const visibilityObserver = new IntersectionObserver(entries => {
    visible = entries[0].isIntersecting;
    syncMotion();
  });
  const sizeObserver = new ResizeObserver(resize);
  function fallback() {
    if (failed) return;
    failed = true;
    cancelAnimationFrame(frame);
    sizeObserver.disconnect();
    visibilityObserver.disconnect();
    host.classList.remove('is-ready');
    geometry.dispose();
    material.dispose();
    texture.dispose();
    renderer.dispose();
    renderer.domElement.remove();
    pointerSurface.removeEventListener('pointermove', onPointerMove);
    pointerSurface.removeEventListener('pointerleave', onPointerLeave);
    reducedMotion.removeEventListener('change', onPreference);
    document.removeEventListener('visibilitychange', syncMotion);
  }
  renderer.domElement.addEventListener('webglcontextlost', event => { event.preventDefault(); fallback(); }, { once: true });
  host.append(renderer.domElement);
  resize();
  if (renderer.getContext().isContextLost()) { fallback(); return; }
  host.classList.add('is-ready');
  // Keep the accessible name on the illustration while avoiding duplicate text.
  host.querySelector('img').alt = '';
  pointerSurface.addEventListener('pointermove', onPointerMove, { passive: true });
  pointerSurface.addEventListener('pointerleave', onPointerLeave);
  reducedMotion.addEventListener('change', onPreference);
  document.addEventListener('visibilitychange', syncMotion);
  window.addEventListener('pagehide', event => { if (!event.persisted) fallback(); });
  sizeObserver.observe(host);
  visibilityObserver.observe(host);
  syncMotion();
}

createScene().catch(() => {
  // The original SVG is already visible; no interaction depends on WebGL.
  host.classList.remove('is-ready');
});
