// RSA.tsxの修正
import { useEffect } from 'react';
import Header from '../components/Header';

const RSA = () => {
  useEffect(() => {
    // 既存の全要素を削除
    document.querySelectorAll('#rsa-app').forEach(el => el.remove());
    
    // StrictModeによる二重実行を防ぐフラグ
    let mounted = true;
    
    import('../lib/rsa/rsa').then(module => {
      if (mounted) {
        module.main();
      }
    });
    
    return () => {
      mounted = false;
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
