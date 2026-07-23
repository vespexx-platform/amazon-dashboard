# Amazon 판매 대시보드 (비밀번호 보호)

아마존 Sales & Traffic 데이터를 보여주는 정적 웹 대시보드. GitHub Pages 호스팅.

## 왜 이렇게 만들었나

- org가 **free 플랜 + private 레포**라 private 레포로는 Pages를 못 올림 → **공개 레포** 사용.
- 대신 데이터를 **클라이언트 암호화**: 빌드 때 `data.js`를 AES-GCM으로 암호화(비밀번호 파생 키).
  공개 URL에는 **암호문만** 노출되고, 브라우저에서 비밀번호로 복호화해야 숫자가 보임.
- 데이터는 빌드 시점에 구워져 들어가므로 **Make API 토큰이 브라우저에 노출되지 않음**.

## 동작

```
GitHub Actions (매일 18:05 KST)
  → build_data.py: Make Data Store 'latest' 읽기
    → 시계열 가공 → PBKDF2(SHA-256, 200k) + AES-GCM 암호화 → site/data.js
  → GitHub Pages 배포
브라우저: index.html → 비밀번호 입력 → Web Crypto 복호화 → 차트/표 렌더
```

## 설정

### GitHub Secrets
| Secret | 설명 |
|---|---|
| `MAKE_API_TOKEN` | Make API 토큰 |
| `MAKE_ZONE` | 예: `us2.make.com` |
| `MAKE_STORE_ID` | Data Store id (`latest`) |
| `DASHBOARD_PASSWORD` | 대시보드 열람 비밀번호 |

### Pages 활성화
Settings → Pages → Source: **GitHub Actions**.

### 실행
- 자동: 매일 18:05 KST cron.
- 수동: Actions → Build & Deploy Dashboard → Run workflow.

## 보안 메모

- 보호 강도는 **비밀번호 세기**에 달림(PBKDF2 200k + AES-256-GCM). 긴 비밀번호 권장.
- 공유 비밀번호(개인별 인증 아님). 비번을 아는 사람은 복호화 가능.
- `robots noindex`로 검색 노출 차단. 단, URL을 아는 사람은 접근 가능(그래서 암호화).
- 로컬 테스트로 만든 `site/data.js`는 커밋 안 됨(.gitignore) — Action이 매번 새로 생성.
