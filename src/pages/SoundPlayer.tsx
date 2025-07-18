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
        <Header
          text={"簡易 音声ファイル プレイヤー"}
          author="砂田翔太"
          showHome
        />
        <div
          className="hover:bg-gray-100 cursor-pointer"
          onClick={() => {
            inputFileRef.current?.click();
          }}
        >
          <DropSoundZone onDropFile={onDropFile}>
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
            <p className="cursor-pointer px-[7dvw] pt-[5dvh]">
              {"ここを押してファイルを読み込む"}{" "}
            </p>
            <p className="p-[10px]">{"または"}</p>
            <p className="mx-[7dvw] mb-[5dvh]">
              {"ここにファイルをドロップして読み込む"}
            </p>
          </DropSoundZone>
        </div>

        <div className="m-[10px] flex flex-col items-center justify-center">
          <p className="text-xl">{"【読込中のファイル】"}</p>
          <p className="text-xl">
            {file ? file.name : "☠️読み込んでいません☠️"}
          </p>
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
        <div className="flex flex-row">
          <Button
            text={"再生位置を最初に戻す"}
            onClick={() => {
              if (playerRef.current?.audio?.current) {
                playerRef.current.audio.current.pause();
                playerRef.current.audio.current.currentTime = 0;
              }
            }}
          />
        </div>
      </div>
    </>
  );
};

export default SoundPlayer;
