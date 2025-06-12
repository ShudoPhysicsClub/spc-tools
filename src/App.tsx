import { BrowserRouter, Route, Routes } from "react-router-dom";
import Index from "./pages/Index";
import SoundPlayer from "./pages/SoundPlayer";
import Random from "./pages/Random";
import ColorConverter from "./pages/ColorConverter";
import MorseChallenge from "./pages/MorseChallenge";

function App() {
  return (
    <>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Index />} />
          <Route path="/sound-player" element={<SoundPlayer />} />
          <Route path="/random" element={<Random />} />
          <Route path="/color-converter" element={<ColorConverter />} />
          <Route path="/morse-challenge" element={<MorseChallenge />} />
        </Routes>
      </BrowserRouter>
    </>
  );
}

export default App;
