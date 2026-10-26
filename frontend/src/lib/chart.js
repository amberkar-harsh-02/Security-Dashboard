// Small helpers shared by the SVG charts.

/** A round axis maximum at or above `value` (never below `floor`). */
export function niceMax(value, floor = 4) {
  if (value <= floor) return floor;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  for (const step of [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) {
    const candidate = step * magnitude;
    if (candidate >= value) return Math.ceil(candidate);
  }
  return Math.ceil(value);
}
