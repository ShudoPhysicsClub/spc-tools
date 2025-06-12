export const availableCharacters: string[][] = [
  // MODE0
  [
    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
  ],
  // MODE1
  ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"],
  // MODE2
  [
    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "0",
  ],
];

export interface MorseData {
  str: string;
  morse: string;
}

export const getMorseData = (mode: number, index: number) => {
  const temp = charToMorse.find(
    (x) => x.str === availableCharacters[mode][index]
  );
  if (temp) {
    return temp;
  }

  if (mode === 0 || mode === 2) {
    return { str: "A", morse: "・ー" };
  } else {
    return { str: "1", morse: "・ーーーー" };
  }
};

export const charToMorse: MorseData[] = [
  // ALPHABETS
  { str: "A", morse: "・ー" },
  { str: "B", morse: "ー・・・" },
  { str: "C", morse: "ー・ー・" },
  { str: "D", morse: "ー・・" },
  { str: "E", morse: "・" },
  { str: "F", morse: "・・ー・" },
  { str: "G", morse: "ーー・" },
  { str: "H", morse: "・・・・" },
  { str: "I", morse: "・・" },
  { str: "J", morse: "・ーーー" },
  { str: "K", morse: "ー・ー" },
  { str: "L", morse: "・ー・・" },
  { str: "M", morse: "ーー" },
  { str: "N", morse: "ー・" },
  { str: "O", morse: "ーーー" },
  { str: "P", morse: "・ーー・" },
  { str: "Q", morse: "ーー・ー" },
  { str: "R", morse: "・ー・" },
  { str: "S", morse: "・・・" },
  { str: "T", morse: "ー" },
  { str: "U", morse: "・・ー" },
  { str: "V", morse: "・・・ー" },
  { str: "W", morse: "・ーー" },
  { str: "X", morse: "ー・・ー" },
  { str: "Y", morse: "ー・ーー" },
  { str: "Z", morse: "ーー・・" },
  // NUMBERS
  { str: "1", morse: "・ーーーー" },
  { str: "2", morse: "・・ーーー" },
  { str: "3", morse: "・・・ーー" },
  { str: "4", morse: "・・・・ー" },
  { str: "5", morse: "・・・・・" },
  { str: "6", morse: "ー・・・・" },
  { str: "7", morse: "ーー・・・" },
  { str: "8", morse: "ーーー・・" },
  { str: "9", morse: "ーーーー・" },
  { str: "0", morse: "ーーーーー" },
];
