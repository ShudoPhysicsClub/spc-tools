import { useState, useEffect, useRef } from "react";
import AudioPlayer from "react-h5-audio-player";
import "react-h5-audio-player/lib/styles.css";
import Button from "../components/Button";
import Header from "../components/Header";

const SoundPlayer = () => {
  const [file, setFile] = useState<File>();
  const [audioUrl, setAudioUrl] = useState<string>();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const playerRef = useRef<any>(null); // AudioPlayerのref
  const [currentSpeed, setCurrentSpeed] = useState<number>(1);

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
            className="file:cursor-pointer file:p-[2dvh] file:border-black file:border-[2px] file:rounded-[2dvh]"
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
        </div>
        <p>{"↑ここをクリックしてファイルを読み込んでください"}</p>
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

        <p>{"Copyright 2025 ShudoPhysicsClub"}</p>
      </div>
    </>
  );
};

export default SoundPlayer;
