import { useState } from "react";
import Button from "../components/Button";
import Header from "../components/Header";

const Random = () => {
  const [result, setResult] = useState<string>("-1");

  const [min, setMin] = useState<number>(0);
  const [max, setMax] = useState<number>(0);

  return (
    <>
      <div className="flex flex-col items-center justify-center">
        <Header text={"乱数メーカー"} author={"砂田翔太"} showHome />
        <div className="flex flex-row m-[3px]">
          <label className="m-[5px]" htmlFor="min">
            {"最小値"}
          </label>
          <input
            className="border-black border-[1px] p-[3px]"
            type="number"
            name="min"
            id="min"
            defaultValue={0}
            onChange={(x) => setMin(x.currentTarget.valueAsNumber)}
          />
        </div>
        <div className="flex flex-row m-[3px]">
          <label className="m-[5px]" htmlFor="max">
            {"最大値"}
          </label>
          <input
            className="border-black border-[1px] p-[3px]"
            type="number"
            name="max"
            id="max"
            defaultValue={0}
            onChange={(x) => setMax(x.currentTarget.valueAsNumber)}
          />
        </div>
        <p>{"抽選結果に、最大値は含まれます。"}</p>
        <p>{"例: 1以上40以下の乱数を生成するとき → 最小値: 1、最大値: 40"}</p>
        <Button
          text={"抽選"}
          onClick={() => {
            if (min > max) {
              alert(
                "最大値が最小値より小さいです。最大値は最小値より大きい必要があります。",
              );
            }

            const temp1 = Math.random() * (max + 1 - min) + min;
            const temp2 = Math.floor(temp1);
            setResult(temp2.toString());
          }}
        />
        <div className="flex flex-col items-center justify-center">
          {result ? (
            <>
              <p>{"抽選結果"}</p>
              <p className="text-5xl">{result === "-1" ? "" : result}</p>
            </>
          ) : (
            <></>
          )}
        </div>
      </div>
    </>
  );
};

export default Random;
