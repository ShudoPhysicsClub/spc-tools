import { useEffect, useRef } from 'react';
import Header from '../components/Header';

const RSA = () => {
  const initialized = useRef(false);

  useEffect(() => {
    // 既に初期化済みならスキップ
    if (initialized.current) return;
    
    initialized.current = true;
    
    import('../lib/rsa/rsa').then(module => {
      module.main();
    });
  }, []);

  return (
    <>
      <Header text="RSA暗号" author="Kazuhiro-Tokumoto" showHome={true} />
    </>
  );
};

export default RSA;
