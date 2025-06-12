export const shuffle = <T>(array: T[]): T[] => {
  const clone = [...array];

  for (let i = clone.length - 1; i >= 0; i--) {
    const rand = Math.floor(Math.random() * (i + 1));
    const tmp = clone[i];
    clone[i] = clone[rand];
    clone[rand] = tmp;
  }

  return clone;
};
