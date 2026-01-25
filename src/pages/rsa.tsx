import { useEffect } from 'react';
import Header from '../components/Header';

const RSA = () => {
  useEffect(() => {
    let cleanup: (() => void) | undefined;
    
    import('../lib/rsa/rsa').then(module => {
      module.main();
      
      // クリーンアップ関数（コンポーネントがアンマウントされたら削除）
      cleanup = () => {
        // RSAtool で追加した要素を削除
        document.querySelector('#rsa-app')?.remove();
      };
    });
    
    return () => {
      cleanup?.();
    };
  }, []);

  return (
    <>
      <Header text="RSA暗号" author="Kazuhiro-Tokumoto" showHome={true} />
    </>
  );
};

export default RSA;
