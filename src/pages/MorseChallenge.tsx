import { useEffect, useRef, useState } from "react";
import Header from "../components/Header";
import { getMorseData, type MorseData } from "../data/morse";
import { genRandomNumbers } from "../functions/random";
import Button from "../components/Button";
import { v4 as uuid } from "uuid";
import { shuffle } from "../functions/shuffle";

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

    // 正解
    const indexes = genRandomNumbers(
      def_mode == 0 ? 26 : def_mode == 1 ? 10 : 36,
      numQuestions
    );
    const array: MorseData[] = [];
    const array2: MorseData[][] = [];
    for (let i = 0; i < indexes.length; i++) {
      const data = getMorseData(def_mode, indexes[i]);
      array.push(data);

      // 選択肢
      const indexes2 = genRandomNumbers(
        def_mode == 0 ? 26 : def_mode == 1 ? 10 : 36,
        3
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
        <Header text={"モールス チャレンジ"} showHome />
        <p>
          {
            "「モールス チャレンジ」は、モールス信号を覚える楽しいゲームです。\n設定に基づいて、10個の問題をランダムに出題します。"
          }
        </p>
        <label>
          {"モードを選んでください:"}
          <select
            ref={mode_select_ref}
            name="mode"
            id="mode"
            value={currentMode}
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
        <label>
          {"タイプを選んでください:"}
          <select
            ref={type_select_ref}
            name="type"
            id="type"
            value={currentType}
            onChange={(e) => {
              localStorage.setItem(ls_morse_type, e.target.value);
              setCurrentType(Number(e.target.value));
            }}
          >
            <option value={0}>{"モールス → 文字"}</option>
            <option value={1}>{"文字 → モールス"}</option>
          </select>
        </label>

        {isStarted ? (
          <>
            {def_type === 0 ? (
              <>
                <p>{"このモールス信号に対応する文字を選びましょう。"}</p>
                <p>{questions[currentQuestionNum].morse}</p>
                <div className="flex flex-row">
                  {selections[currentQuestionNum].map((x) => (
                    <Button
                      key={uuid()}
                      text={x.str}
                      onClick={() => {
                        if (x.str === questions[currentQuestionNum].str) {
                          alert("正解!");
                        } else {
                          alert("不正解!");
                        }
                        setCurrentQuestionNum(currentQuestionNum + 1);
                      }}
                    />
                  ))}
                </div>
              </>
            ) : (
              <>
                <p>{"この文字に対応するモールス信号を選びましょう。"}</p>
                <p>{questions[currentQuestionNum].str}</p>
                <div className="flex flex-row">
                  {selections[currentQuestionNum].map((x) => (
                    <Button
                      key={uuid()}
                      text={x.morse}
                      onClick={() => {
                        if (x.str === questions[currentQuestionNum].str) {
                          alert("正解!");
                        } else {
                          alert("不正解!");
                        }
                        setCurrentQuestionNum(currentQuestionNum + 1);
                      }}
                    />
                  ))}
                </div>
              </>
            )}
          </>
        ) : (
          <>
            <p
              className="m-[10px] cursor-pointer border-[1px] border-black rounded-2xl p-[10px] text-2xl"
              onClick={onStart}
            >
              {"始める"}
            </p>
          </>
        )}
      </div>
    </>
  );
};

export default MorseChallenge;
