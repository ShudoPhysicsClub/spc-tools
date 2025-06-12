import { useNavigate } from "react-router-dom";
import Button from "../components/Button";
import Header from "../components/Header";

const Index = () => {
  const navigate = useNavigate();

  return (
    <>
      <div className="flex flex-col items-center justify-center">
        <Header text={"物理班ツール置き場"} showHome={false} />
        <div className="m-[5px]">
          <Button
            className="text-2xl m-[5px] border-black border-[1px] cursor-pointer"
            onClick={() => navigate("/sound-player")}
            text={"簡易 音声ファイル プレイヤー"}
          />
          <Button
            className="text-2xl m-[5px] border-black border-[1px] cursor-pointer"
            onClick={() => navigate("/random")}
            text={"乱数メーカー"}
          />
          <Button
            className="text-2xl m-[5px] border-black border-[1px] cursor-pointer"
            onClick={() => navigate("/color-converter")}
            text={"カラーコンバーター"}
          />
          <Button
            className="text-2xl m-[5px] border-black border-[1px] cursor-pointer"
            onClick={() => navigate("/morse-challenge")}
            text={"モールス チャレンジ"}
          />
        </div>
      </div>
    </>
  );
};

export default Index;
