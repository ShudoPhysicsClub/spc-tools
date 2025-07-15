import { useEffect, useRef, useState } from "react";
import Header from "../components/Header";
import { getMorseData, type MorseData } from "../data/morse";
import { genRandomNumbers } from "../functions/random";
import { v4 as uuid } from "uuid";
import { shuffle } from "../functions/shuffle";

interface Result {
  is_correct: boolean;
  answer: MorseData;
  selection: MorseData;
}

const MorseChallenge = () => {
  const ls_morse_mode = "morse_mode";
  const ls_morse_type = "morse_type";

  const mode_select_ref = useRef<HTMLSelectElement>(null);
  const type_select_ref = useRef<HTMLSelectElement>(null);

  const [isStarted, setIsStarted] = useState<boolean>(false);
  const [currentMode, setCurrentMode] = useState<number>(0);
  // MODE0: only alphabets
  // MODE1: only numbers
  // MODE2: alphabets and numbers
  const [currentType, setCurrentType] = useState<number>(0);
  // TYPE0: morse to string
  // TYPE1: string to morse

  const [questions, setQuestions] = useState<MorseData[]>([]);
  const [selections, setSelections] = useState<MorseData[][]>([]);

  const [currentQuestionNum, setCurrentQuestionNum] = useState<number>(0);

  const [questionResult, setQuestionResult] = useState<Result | null>(null);

  const [isShowResult, setIsShowResult] = useState<boolean>(false);

  const [correctCount, setCorrectCount] = useState<number>(0);
  const [missingMorse, setMissingMorse] = useState<MorseData[]>([]);

  const numQuestions: number = 10;

  const mode_str = localStorage.getItem(ls_morse_mode);
  const type_str = localStorage.getItem(ls_morse_type);

  const def_mode = mode_str ? Number.parseInt(mode_str) : 0;
  const def_type = type_str ? Number.parseInt(type_str) : 0;

  useEffect(() => {
    const modeSelect = mode_select_ref.current;
    if (modeSelect) {
      modeSelect.value = def_mode.toString();
    }

    const typeSelect = type_select_ref.current;
    if (typeSelect) {
      typeSelect.value = def_type.toString();
    }
  });

  const onStart = () => {
    setCurrentQuestionNum(0);
    setMissingMorse([]);
    setIsShowResult(false);
    setQuestionResult(null);
    setCorrectCount(0);

    // 正解
    const indexes = genRandomNumbers(
      def_mode == 0 ? 26 : def_mode == 1 ? 10 : 36,
      numQuestions,
    );
    const array: MorseData[] = [];
    const array2: MorseData[][] = [];
    for (let i = 0; i < indexes.length; i++) {
      const data = getMorseData(def_mode, indexes[i]);
      array.push(data);

      // 選択肢
      const indexes2 = genRandomNumbers(
        def_mode == 0 ? 26 : def_mode == 1 ? 10 : 36,
        3,
      );
      const temp_data = [data];
      for (let j = 0; j < indexes2.length; j++) {
        const temp2 = getMorseData(def_mode, indexes2[j]);
        if (!temp_data.includes(temp2)) {
          temp_data.push(temp2);
        }
      }
      array2.push(shuffle<MorseData>(temp_data));
    }
    setQuestions(array);
    setSelections(array2);

    setIsStarted(true);
  };

  return (
    <>
      <div className="flex flex-col items-center justify-center">
        <Header text={"モールス チャレンジ"} author={"砂田翔太"} showHome />
        <p>
          {
            "「モールス チャレンジ」は、モールス信号を覚える楽しいゲームです。\n設定に基づいて、10個の問題をランダムに出題します。"
          }
        </p>

        <div className="m-[10px]">
          {isStarted ? (
            <>
              <div className="border-[1px] border-black rounded-2xl p-[30px]">
                <div className="flex flex-col items-center justify-center m-[10px]">
                  <p className="text-2xl">
                    {def_type == 0
                      ? "このモールス信号に対応する文字を選びましょう。"
                      : "この文字に対応するモールス信号を選びましょう。"}
                  </p>
                  <p className="text-2xl m-[10px]">
                    {"「"}
                    {def_type == 0
                      ? questions[currentQuestionNum].morse
                      : questions[currentQuestionNum].str}
                    {"」"}
                  </p>
                  <div className="flex flex-row">
                    {selections[currentQuestionNum].map((x, i) => (
                      <button
                        className="border-black text-2xl border-[2px] rounded-[10px] px-[20px] py-[10px] m-[10px] cursor-pointer hover:bg-gray-100"
                        key={uuid()}
                        onClick={() => {
                          if (x.str === questions[currentQuestionNum].str) {
                            setQuestionResult({
                              is_correct: true,
                              answer: questions[currentQuestionNum],
                              selection: selections[currentQuestionNum][i],
                            });
                            setCorrectCount(correctCount + 1);
                          } else {
                            setQuestionResult({
                              is_correct: false,
                              answer: questions[currentQuestionNum],
                              selection: selections[currentQuestionNum][i],
                            });
                            setMissingMorse([
                              ...missingMorse,
                              questions[currentQuestionNum],
                            ]);
                          }

                          if (currentQuestionNum < numQuestions - 1) {
                            setCurrentQuestionNum(currentQuestionNum + 1);
                            console.log(currentQuestionNum);
                          } else {
                            setIsShowResult(true);
                            setIsStarted(false);
                          }
                        }}
                      >
                        {def_type == 0 ? x.str : x.morse}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </>
          ) : (
            <>
              {isShowResult ? (
                <>
                  <div className="border-[1px] border-black rounded-2xl px-[30px] py-[15px] flex flex-col items-center justify-center">
                    <p className="text-3xl">{"終了!"}</p>
                    <div className="m-[10px] flex flex-col items-center justify-center">
                      <p className="text-xl">{"あなたの結果"}</p>
                      <p className="text-xl">
                        {"正解数: "}
                        {correctCount}
                        {"/"}
                        {numQuestions}
                      </p>
                    </div>
                    {missingMorse.length == 0 ? (
                      <p className="text-2xl">{"🎉全問正解🎉"}</p>
                    ) : (
                      <div className="m-[10px] flex flex-col items-center justify-center">
                        <p>{"間違えたモールス一覧"}</p>
                        <table className="max-w-[150px] w-[100%] border-t-[1px] border-l-[1px] border-r-[1px]">
                          <thead>
                            <tr className="">
                              <th className="w-[50px] border-r-[1px] border-b-[2px]">
                                {"文字"}
                              </th>
                              <th className="w-[100px] border-b-[2px]">
                                {"モールス"}
                              </th>
                            </tr>
                          </thead>
                          <tbody>
                            {missingMorse.map((x) => (
                              <tr className="" key={uuid()}>
                                <td
                                  style={{ textAlign: "center" }}
                                  className="border-b-[1px] border-r-[1px]"
                                >
                                  {x.str}
                                </td>
                                <td
                                  style={{ textAlign: "left" }}
                                  className="border-b-[1px] pl-[7px]"
                                >
                                  {x.morse}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                        <p className="text-xl">{"☠️継続は力なり☠️"}</p>
                      </div>
                    )}
                  </div>
                </>
              ) : (
                <></>
              )}
            </>
          )}
        </div>
        <div className="flex flex-col items-center justify-center">
          {questionResult ? (
            <div className="flex flex-col m-[5px]">
              <p className="text-6xl flex justify-center">
                {questionResult.is_correct ? "⭕️" : "❌️"}
              </p>
              <div className="m-[15px]">
                <p className="text-xl flex justify-end">
                  {"正解: 「"}
                  {def_type == 0
                    ? `${questionResult.answer.str} (${questionResult.answer.morse})`
                    : `${questionResult.answer.morse} (${questionResult.answer.str})`}
                  {"」"}
                </p>
                <p className="text-xl flex justify-end">
                  {"あなたの回答: 「"}
                  {def_type == 0
                    ? `${questionResult.selection.str} (${questionResult.selection.morse})`
                    : `${questionResult.selection.morse} (${questionResult.selection.str})`}
                  {"」"}
                </p>
              </div>
            </div>
          ) : (
            <></>
          )}
        </div>
        {!isStarted ? (
          <>
            <div className="flex flex-col m-[5px]">
              <label className="m-[2px]">
                {"モードを選んでください:"}
                <select
                  ref={mode_select_ref}
                  name="mode"
                  id="mode"
                  value={currentMode}
                  className="border-black border-[1px] rounded-[5px] ml-[5px] p-[2px]"
                  onChange={(e) => {
                    localStorage.setItem(ls_morse_mode, e.target.value);
                    setCurrentMode(Number(e.target.value));
                  }}
                >
                  <option value={0}>{"アルファベット のみ"}</option>
                  <option value={1}>{"数字 のみ"}</option>
                  <option value={2}>{"アルファベット + 数字"}</option>
                </select>
              </label>
              <label className="m-[2px]">
                {"タイプを選んでください:"}
                <select
                  ref={type_select_ref}
                  name="type"
                  id="type"
                  value={currentType}
                  className="border-black border-[1px] rounded-[5px] ml-[5px] p-[2px]"
                  onChange={(e) => {
                    localStorage.setItem(ls_morse_type, e.target.value);
                    setCurrentType(Number(e.target.value));
                  }}
                >
                  <option value={0}>{"モールス → 文字"}</option>
                  <option value={1}>{"文字 → モールス"}</option>
                </select>
              </label>
            </div>
            <p
              className="flex justify-center hover:bg-gray-100 m-[10px] cursor-pointer border-[1px] border-black rounded-2xl p-[10px] text-2xl"
              onClick={onStart}
            >
              {"始める"}
            </p>
          </>
        ) : (
          <></>
        )}
      </div>
    </>
  );
};

export default MorseChallenge;
