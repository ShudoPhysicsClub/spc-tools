import { type ButtonHTMLAttributes } from "react";

type Props = {
  text: string;
} & ButtonHTMLAttributes<HTMLButtonElement>;

const Button = (props: Props) => {
  const { text, ...buttonProps } = props;
  return (
    <button className="border-black border-[2px] rounded-[10px] p-[10px] m-[10px] cursor-pointer hover:bg-gray-100" {...buttonProps}>
      {text}
    </button>
  );
};

export default Button;
