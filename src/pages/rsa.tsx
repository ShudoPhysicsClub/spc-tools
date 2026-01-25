import { useEffect } from 'react';
import Header from '../components/Header';

const RSA = () => {
  useEffect(() => {
    // あなたの rsa.ts の main() を呼ぶ
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
