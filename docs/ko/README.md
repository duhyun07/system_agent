# 한국어 문서

System Agent는 Google의 공식 **kernelCTF** 프로그램 전용 로컬 우선(local-first)
Linux 커널 연구 플랫폼입니다. 공식 문서 기반 환경 설정(온라인)에서 시작해,
오프라인 커널 소스 분석·크래시 트리아지·보고서 작성까지 이어집니다. 두 AI 책임을
엄격히 분리합니다.

| 책임 | 프로바이더 | 단계 |
| --- | --- | --- |
| 공식 문서 조사, 환경 준비, 검증 | **OpenAI GPT** (온라인) | A |
| 커널 소스 분석, 후보 발견, 크래시 트리아지, 리그레션, 보고 | **Ollama** (오프라인) | B |

{% hint style="warning" %}
**범위.** 산출물은 근거 기반 근본원인 분석·트리아지·보고서이며, 익스플로잇 코드,
권한 상승, 지속성, 커널 보호 우회는 구현하지 않습니다. 후보 발견은 재현 전까지
항상 **가설**이며, 검증되지 않은 발견을 확정 취약점으로 표시하지 않습니다. 동적
테스트는 승인된 격리 VM에서만 수행합니다.
{% endhint %}

## 설치

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/system-agent doctor
```

테스트(이 호스트의 pytest 플러그인 충돌 회피):

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q
```

## 모드

| 모드 | 프로바이더 | 용도 |
| --- | --- | --- |
| `offline` (기본) | 로컬 Ollama | Phase B 연구 |
| `online` | OpenAI Responses API | Phase A 문서/설정 |
| `hybrid` | 연구는 Ollama, 클라우드는 승인된 명령만 | 혼합 |

GPU: `configs/offline.yaml`의 `num_gpu: 999`가 GPU에 최대한 레이어를 오프로드합니다
(RTX 4060 8GB). `ollama ps`에서 `100% GPU`로 확인. CPU 전용은 `num_gpu: 0`.
자세한 내용은 [Modes and Providers](../modes-and-providers.md).

## 워크플로 단계

```
UNINITIALIZED → ONLINE_DOCUMENTATION → ONLINE_PROVISIONING
            → ENVIRONMENT_VERIFICATION → READY_FOR_OFFLINE
            → OFFLINE_RESEARCH → LOCAL_REPORTING
```

핵심: `OFFLINE_RESEARCH`에 진입하면 자동으로 온라인 단계로 **되돌아가지 않습니다**
(오류가 온라인 복귀 사유가 되지 않음). 설정 재진입은 사용자의 명시적 행위
(`reset_online`)로만 가능합니다. 또한 오프라인 연구는 모드 허용 목록과 무관하게
모든 네트워크 스킬이 제거된 상태로 실행됩니다. 상세:
[Workflow Phases](../workflow-phases.md).

## 처음 사용

```bash
system-agent doctor
system-agent status

# 온라인 설정 (Phase A)
system-agent mode set online
system-agent setup docs
system-agent setup known-issues
system-agent setup target select --instance lts --source /path/to/linux
system-agent setup verify

# 오프라인 연구 (Phase B)
system-agent mode set offline
system-agent research start --offline
system-agent research source --subsystem net/tls

# 크래시 트리아지 / 보고서
system-agent crash triage --input ./crash.log --source /path/to/linux
system-agent findings list
system-agent report generate --program kctf
```

전체 명령은 [CLI Reference](../cli-reference.md) 참고.

## 크래시 신규성(Novelty) 판정

`crash triage`는 (신뢰할 수 없는) 로그를 파싱하고 원본을 **불변**(`0444`)으로
저장한 뒤, ① 로컬 크래시 인덱스(중복), ② 알려진 이슈 레지스트리, ③ 로컬 커널
git 히스토리의 업스트림 수정 커밋(1-day 지표)을 대조합니다.

- **알려짐(known)** → 다른 크래시를 계속 탐색하도록 권고.
- **신규(novel)** → 후보 발견(가설)을 기록하고 `reports/<finding_id>.md`에 보고서
  초안을 작성.

알려진 이슈는 온라인(`setup known-issues`) 또는 수동(`crash known add`)으로 채웁니다.
상세: [Crash Triage and Novelty](../crash-triage.md).

## 스킬

파일시스템 8개, 네트워크 2개, 커널 연구 11개(소스 검색/함수·콜그래프 조회/config
조회/commit diff/로그 파싱/크래시 중복제거/빌드 정보/커버리지/VM 상태/그리고
CLI 전용·승인 게이트 `kernel_test_run`). 제한 없는 셸 스킬은 없습니다. 상세:
[Skills](../skills.md).

## 보안 모델 요약

권한은 Python에서 강제됩니다. 파일 접근은 인가 루트만 사용하고 경로 이탈·심링크를
거부합니다. 오프라인은 네트워크 차단, 온라인/하이브리드는 도메인 허용 목록 +
DNS 검증 + IP 고정. 원본 크래시 증거는 불변. 감사 로그는 해시만 기록합니다.
동적 테스트(`kernel_test_run`)는 CLI 전용·승인·VM 격리 확인 필수이며 모델 생성
코드를 실행하지 않습니다. 상세: [Security Model](../security.md).

## 제한 사항

- `syz-manager` 미설치 → syzkaller 어댑터는 읽기 전용(퍼징 오케스트레이션 없음).
- 선택적 코드 모델 `qwen2.5-coder:7b`는 기본 미설치(`ollama pull`로 활성화).
- 콜그래프/함수 조회는 휴리스틱(cscope/clang 인덱스 미사용).
- WSL2에서 KVM 가속은 보장되지 않음(`kernel_vm_status`가 실제 상태 보고).
- **Abliteration(거부 동작 제거) 기능은 의도적으로 제공하지 않습니다.**

전체 제한 목록: [Limitations](../limitations.md).
