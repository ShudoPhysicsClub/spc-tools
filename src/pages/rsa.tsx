import { useEffect } from 'react';
import Header from '../components/Header';

const RSA = () => {
  useEffect(() => {
    // 既存の全要素を削除
    document.querySelectorAll('#rsa-app').forEach(el => el.remove());
    
    import('../lib/rsa/rsa').then(module => {
      module.main();
    });
    
    return () => {
      // アンマウント時に削除
      document.querySelectorAll('#rsa-app').forEach(el => el.remove());
    };
  }, []);

  return (
    <>
      <Header text="RSA暗号" author="Kazuhiro-Tokumoto" showHome={true} />
    </>
  );
};

export default RSA;
