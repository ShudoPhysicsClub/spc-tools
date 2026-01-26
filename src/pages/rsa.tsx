// RSA.tsxの修正
import { useEffect } from 'react';
import Header from '../components/Header';

const RSA = () => {
  useEffect(() => {
    // viewport設定（拡大禁止）
    const viewport = document.querySelector('meta[name="viewport"]');
    const originalContent = viewport?.getAttribute('content');
    
    if (viewport) {
      viewport.setAttribute(
        'content',
        'width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no'
      );
    }

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
      
      // viewport設定を元に戻す
      if (viewport && originalContent) {
        viewport.setAttribute('content', originalContent);
      }
    };
  }, []);

  return (
    <>
      <Header text="RSA暗号" author="Kazuhiro-Tokumoto" showHome={true} />
    </>
  );
};

export default RSA;
