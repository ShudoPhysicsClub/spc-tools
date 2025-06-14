import Header from "../components/Header";
import RemarkMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import remarkBreaks from "remark-breaks";
import remarkHtml from "remark-html";
import remarkRehype from "remark-rehype";
import remarkMath from "remark-math";
import rehypeKatex from "rehype-katex";
import rehypeRaw from "rehype-raw";
import { useState } from "react";
import "../styles/markdown.css";

const Markdown = () => {
  const [markdown, setMarkdown] = useState<string>("");

  return (
    <>
      <div className="flex flex-col items-center justify-center">
        <Header text={"マークダウンエディタ"} showHome />
        <p>
          {
            "物理班の記事や作品紹介で使用されているマークダウンの方式で、マークダウンを編集できます。"
          }
        </p>
        <div className="flex flex-row w-[80vw] h-[80vh]">
          <div className="w-[50%] m-[10px]">
            <p>{"プレーンテキスト"}</p>
            <textarea
              className="w-[100%] h-[100%] resize-none p-[10px] overflow-auto border-[1px] border-black rounded-[10px]"
              name="plane_text"
              id="plane_text"
              value={markdown}
              onChange={(e) => setMarkdown(e.target.value)}
              wrap="off"
            />
          </div>
          <div className="w-[50%] m-[10px]">
            <p>{"マークダウン"}</p>
            <div className="markdown flex-grow h-[100%] overflow-auto border-[1px] border-black rounded-[10px] p-[10px]">
              <RemarkMarkdown
                remarkPlugins={[
                  remarkBreaks,
                  remarkGfm,
                  remarkHtml,
                  remarkRehype,
                  remarkMath,
                ]}
                rehypePlugins={[rehypeKatex, rehypeRaw]}
              >
                {markdown}
              </RemarkMarkdown>
            </div>
          </div>
        </div>
        <div className="fixed bottom-[2vh]">
          <button
            className="cursor-pointer border-[1px] border-black rounded-[10px] p-[10px]"
            onClick={() => {
              const blob = new Blob([markdown], { type: "text/plain" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = "markdown.md";
              document.body.appendChild(a);
              a.click();
              document.body.removeChild(a);
              URL.revokeObjectURL(url);
            }}
          >
            {"保存する"}
          </button>
        </div>
      </div>
    </>
  );
};

export default Markdown;
