const MIN_STABLE_LENGTH = 10;

export function is_stream_stable(prev: string, curr: string): boolean {
  if (curr.length < MIN_STABLE_LENGTH) return false;
  return prev === curr;
}
