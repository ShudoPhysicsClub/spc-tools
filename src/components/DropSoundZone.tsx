import type { DragEvent, ReactNode } from "react";
import { useState } from "react";

type Props = {
  onDropFile: (file: File) => void;
  children: ReactNode;
};

const DropSoundZone = (props: Props) => {
  const [isDragActive, setIsDragActive] = useState<boolean>(false);

  const onDragEnter = (e: DragEvent<HTMLDivElement>) => {
    if (e.dataTransfer.items && e.dataTransfer.items.length > 0) {
      setIsDragActive(true);
    }
  };

  const onDragLeave = () => {
    setIsDragActive(false);
  };

  const onDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      if (e.dataTransfer.files.length === 1) {
        props.onDropFile(e.dataTransfer.files[0]);
      } else {
        alert("音声ファイルは一つだけドラッグしてください。");
      }

      e.dataTransfer.clearData();
    }
  };

  return (
    <div
      onDragEnter={onDragEnter}
      onDragLeave={onDragLeave}
      onDragOver={(e) => e.preventDefault()}
      onDrop={onDrop}
      className={"hover:bg-gray-100 border-2 border-dashed border-gray-400 rounded-lg p-4 " + (isDragActive ? "bg-gray-200" : "bg-white") + " flex flex-col items-center justify-center"}
    >
      {props.children}
    </div>
  );
};

export default DropSoundZone;
