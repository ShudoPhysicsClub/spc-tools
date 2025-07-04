import { useNavigate } from "react-router-dom";

const Header = (props: { text: string; author: string; showHome: boolean }) => {
  const navigate = useNavigate();

  return (
    <>
      <div className="flex flex-row">
        {props.showHome ? (
          <p
            className="text-xl mb-[3dvh] justify-center items-center flex mr-[5dvh] cursor-pointer"
            onClick={() => navigate("/")}
          >
            {"ホームへ"}
          </p>
        ) : (
          <></>
        )}
        <p className="text-3xl mb-[3dvh]">{props.text}</p>
        <p className="text-xl ml-[10px] mb-[3dvh]">
          {"作成者: "}
          {props.author}
        </p>
      </div>
    </>
  );
};

export default Header;
