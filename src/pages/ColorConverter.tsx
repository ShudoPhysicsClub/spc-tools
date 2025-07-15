import { useEffect, useState } from "react";
import Header from "../components/Header";

const hexToRgb = (hex: string): { r: number; g: number; b: number } | null => {
  const cleaned = hex.replace(/^#/, "");
  if (!/^([0-9A-Fa-f]{3}){1,2}$/.test(cleaned)) return null;

  const fullHex =
    cleaned.length === 3
      ? cleaned
          .split("")
          .map((c) => c + c)
          .join("")
      : cleaned;

  const bigint = parseInt(fullHex, 16);
  return {
    r: (bigint >> 16) & 255,
    g: (bigint >> 8) & 255,
    b: bigint & 255,
  };
};

const rgbToHex = (r: number, g: number, b: number): string => {
  const clamp = (val: number) => Math.max(0, Math.min(255, val));
  return (
    "#" +
    [clamp(r), clamp(g), clamp(b)]
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("")
  );
};

const rgbToHsl = (
  r: number,
  g: number,
  b: number,
): { h: number; s: number; l: number } => {
  r /= 255;
  g /= 255;
  b /= 255;
  const max = Math.max(r, g, b),
    min = Math.min(r, g, b);
  const l = (max + min) / 2;

  let h = 0,
    s = 0;
  if (max !== min) {
    const d = max - min;
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    switch (max) {
      case r:
        h = (g - b) / d + (g < b ? 6 : 0);
        break;
      case g:
        h = (b - r) / d + 2;
        break;
      case b:
        h = (r - g) / d + 4;
        break;
    }
    h *= 60;
  }
  return { h: Math.round(h), s: Math.round(s * 100), l: Math.round(l * 100) };
};

const hslToRgb = (
  h: number,
  s: number,
  l: number,
): { r: number; g: number; b: number } => {
  s /= 100;
  l /= 100;
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const x = c * (1 - Math.abs(((h / 60) % 2) - 1));
  const m = l - c / 2;

  let r = 0,
    g = 0,
    b = 0;
  if (0 <= h && h < 60) [r, g, b] = [c, x, 0];
  else if (h < 120) [r, g, b] = [x, c, 0];
  else if (h < 180) [r, g, b] = [0, c, x];
  else if (h < 240) [r, g, b] = [0, x, c];
  else if (h < 300) [r, g, b] = [x, 0, c];
  else [r, g, b] = [c, 0, x];

  return {
    r: Math.round((r + m) * 255),
    g: Math.round((g + m) * 255),
    b: Math.round((b + m) * 255),
  };
};

const ColorConverter = () => {
  const [hex, setHex] = useState("#ffffff");
  const [rgb, setRgb] = useState({ r: 255, g: 255, b: 255 });
  const [hsl, setHsl] = useState({ h: 0, s: 0, l: 100 });
  const [lastChanged, setLastChanged] = useState<"hex" | "rgb" | "hsl" | null>(
    null,
  );

  useEffect(() => {
    if (lastChanged === "hex") {
      const rgbVal = hexToRgb(hex);
      if (rgbVal) {
        setRgb(rgbVal);
        setHsl(rgbToHsl(rgbVal.r, rgbVal.g, rgbVal.b));
      }
    }
  }, [hex]);

  useEffect(() => {
    if (lastChanged === "rgb") {
      setHex(rgbToHex(rgb.r, rgb.g, rgb.b));
      setHsl(rgbToHsl(rgb.r, rgb.g, rgb.b));
    }
  }, [rgb]);

  useEffect(() => {
    if (lastChanged === "hsl") {
      const rgbVal = hslToRgb(hsl.h, hsl.s, hsl.l);
      setRgb(rgbVal);
      setHex(rgbToHex(rgbVal.r, rgbVal.g, rgbVal.b));
    }
  }, [hsl]);

  const safeNum = (val: number) => (isNaN(val) ? 0 : val);

  return (
    <div className="flex flex-col items-center justify-center p-[16px]">
      <Header text="カラーコンバーター" author={"tau34"} showHome />

      <div className="m-[6px] flex items-center">
        <label className="mr-[5px]" htmlFor="hex">
          HEX:
        </label>
        <input
          id="hex"
          type="text"
          value={hex}
          onChange={(e) => {
            setHex(e.target.value);
            setLastChanged("hex");
          }}
          className="border border-black p-[5px] w-[100px]"
        />
      </div>

      <div className="m-[6px] flex items-center">
        <label className="mr-[5px]">RGB:</label>
        {["r", "g", "b"].map((key) => (
          <input
            key={key}
            type="number"
            min={0}
            max={255}
            value={rgb[key as keyof typeof rgb]}
            onChange={(e) => {
              setRgb((prev) => ({
                ...prev,
                [key]: safeNum(e.target.valueAsNumber),
              }));
              setLastChanged("rgb");
            }}
            className="w-[60px] mx-[2px] border border-black p-[3px]"
          />
        ))}
      </div>

      <div className="m-[6px] flex items-center">
        <label className="mr-[5px]">HSL:</label>
        {["h", "s", "l"].map((key, idx) => (
          <input
            key={key}
            type="number"
            min={idx === 0 ? 0 : 0}
            max={idx === 0 ? 360 : 100}
            value={hsl[key as keyof typeof hsl]}
            onChange={(e) => {
              setHsl((prev) => ({
                ...prev,
                [key]: safeNum(e.target.valueAsNumber),
              }));
              setLastChanged("hsl");
            }}
            className="w-[60px] mx-[2px] border border-black p-[3px]"
          />
        ))}
      </div>

      <div
        className="w-[100px] h-[100px] border mt-[10px]"
        style={{ backgroundColor: hex }}
      />
    </div>
  );
};

export default ColorConverter;
