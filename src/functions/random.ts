export const genRandomNumbers = (max: number, count: number) => {
  const genArray = [];
  const numArray = [];

  for (let i = 0; i < max; i++) {
    numArray[i] = i;
  }

  for (let j = 0, len = numArray.length; j < count; j++, len--) {
    const rndNum = Math.floor(Math.random() * len);
    genArray.push(numArray[rndNum]);
    numArray[rndNum] = numArray[len - 1];
  }

  // for (let k = 0; k < genArray.length; k++) {
  //   console.log(genArray[k]);
  // }

  return genArray;
};
