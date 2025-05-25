import { BrowserRouter, Route, Routes } from "react-router-dom";
import Index from "./pages/Index";
import SoundPlayer from "./pages/SoundPlayer";
import Random from "./pages/Random";

function App() {
  return (
    <>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Index />} />
          <Route path="/sound-player" element={<SoundPlayer />} />
          <Route path="/random" element={<Random />} />
        </Routes>
      </BrowserRouter>
    </>
  );
}

export default App;
