import "./globals.css";

export const metadata = {
  title: "SubExtractor - Извлечение VPN ключей (VLESS, Hysteria2)",
  description: "Онлайн-утилита для конвертации и извлечения ссылок VLESS, Hysteria2 и др. из подписок приложений Happ, Incy, Hiddify, Clash и Base64-ссылок.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="ru">
      <body>{children}</body>
    </html>
  );
}
