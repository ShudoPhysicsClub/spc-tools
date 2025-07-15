import { useNavigate } from "react-router-dom";

const Header = (props: { text: string; author: string; showHome: boolean }) => {
  const navigate = useNavigate();

  return (
    <>
      <div className="flex flex-row border-b-[1px] w-full justify-center items-center mb-[2dvh]">
        {props.showHome ? (
          <p
            className="text-xl mb-[1dvh] justify-center items-center flex mr-[5dvh] cursor-pointer"
            onClick={() => navigate("/")}
          >
            {"ホームへ"}
          </p>
        ) : (
          <></>
        )}
        <p className="text-3xl mb-[1dvh]">{props.text}</p>
        {/* <p className="text-xl ml-[10px] mb-[3dvh] flex items-center justify-center">
          {"作成者: "}
          {props.author}
        </p> */}
      </div>
    </>
  );
};

export default Header;
