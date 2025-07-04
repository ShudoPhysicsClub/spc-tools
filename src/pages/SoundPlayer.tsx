import { useState, useEffect, useRef } from "react";
import AudioPlayer from "react-h5-audio-player";
import "react-h5-audio-player/lib/styles.css";
import Button from "../components/Button";
import Header from "../components/Header";
import DropSoundZone from "../components/DropSoundZone";

const SoundPlayer = () => {
  const [file, setFile] = useState<File>();
  const [audioUrl, setAudioUrl] = useState<string>();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const playerRef = useRef<any>(null); // AudioPlayerのref
  const [currentSpeed, setCurrentSpeed] = useState<number>(1);

  const inputFileRef = useRef<HTMLInputElement>(null);

  const onDropFile = (file: File) => {
    if (file.type.substring(0, 5) !== "audio") {
      alert("音声ファイルでないものはアップロードできません！");
    } else {
      const fileReader = new FileReader();
      fileReader.onload = () => {
        const imageSrc: string = fileReader.result as string;
        setAudioUrl(imageSrc);
        setFile(file);
      };
      fileReader.readAsDataURL(file);
    }
  };

  useEffect(() => {
    if (file) {
      const url = URL.createObjectURL(file);
      setAudioUrl(url);
      return () => {
        URL.revokeObjectURL(url);
      };
    } else {
      setAudioUrl(undefined);
    }
  }, [file]);

  return (
    <>
      <div className="flex flex-col items-center justify-center">
        <Header text={"簡易 音声ファイル プレイヤー"} showHome />
        <div className="">
          <input
            ref={inputFileRef}
            className="hidden file:cursor-pointer file:p-[2dvh] file:border-black file:border-[2px] file:rounded-[2dvh]"
            type="file"
            name="music_file"
            id="music_file"
            accept="audio/*"
            onChange={(e) => {
              if (e.target.files) {
                setFile(e.target.files[0]);
              }
            }}
          />
          <button
            className="cursor-pointer border-[1px] border-black rounded-2xl px-[30px] py-[20px] hover:bg-gray-100"
            onClick={() => {
              inputFileRef.current?.click();
            }}
          >
            {"ここを押してファイルを読み込む"}
          </button>
        </div>
        <p className="p-[10px]">{"または"}</p>
        <DropSoundZone onDropFile={onDropFile}>
          <p className="m-[10px] cursor-default">
            {"ここにファイルをドロップしてください。"}
          </p>
        </DropSoundZone>

        <div className="m-[10px] flex flex-col items-center justify-center">
          <p>{"読込中のファイル"}</p>
          <p>{file ? file.name : "読み込んでいません"}</p>
        </div>

        <div className="w-[80%] mx-[3dvh] my-[3dvh]">
          <AudioPlayer
            ref={playerRef}
            src={audioUrl}
            showJumpControls={false}
          />
        </div>

        <p className="text-xl">
          {"現在の速度: "}
          <span className="font-bold text-2xl">
            {currentSpeed}
            {"倍"}
          </span>
        </p>

        <div className="flex flex-row">
          <Button
            text={"1倍速"}
            onClick={() => {
              if (playerRef.current?.audio?.current) {
                playerRef.current.audio.current.playbackRate = 1.0;
                setCurrentSpeed(1);
              }
            }}
          />
          <Button
            text={"1.25倍速"}
            onClick={() => {
              if (playerRef.current?.audio?.current) {
                playerRef.current.audio.current.playbackRate = 1.25;
                setCurrentSpeed(1.25);
              }
            }}
          />
          <Button
            text={"1.5倍速"}
            onClick={() => {
              if (playerRef.current?.audio?.current) {
                playerRef.current.audio.current.playbackRate = 1.5;
                setCurrentSpeed(1.5);
              }
            }}
          />
        </div>
      </div>
    </>
  );
};

export default SoundPlayer;
