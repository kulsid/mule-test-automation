# MuleSoft Security Best-Practices Scan

**Pass rate:** 8/10 = **80.0%** (threshold: 80%)
**Status:** PASSED ✅

| ID | Check | Result | Detail |
| --- | --- | --- | --- |
| SEC-001 | HTTPS on all listeners | **FAIL** | src/main/mule/test-automation.xml: listener not HTTPS |
| SEC-002 | HTTPS on all outbound requests | **PASS** | All http:request-connection elements use HTTPS |
| SEC-003 | No hardcoded credentials in Mule XML | **PASS** | No hardcoded credentials found in Mule XML |
| SEC-004 | Secure properties configured for property files | **PASS** | No property files present (nothing to secure) |
| SEC-005 | TLS context on HTTPS listeners | **PASS** | All HTTPS listeners include a tls:context (or none configured) |
| SEC-006 | Wildcard bind (0.0.0.0) limited | **PASS** | 1 listener(s) bound to 0.0.0.0 within demo tolerance |
| SEC-007 | Loggers do not dump full payload/attributes | **PASS** | No loggers dump full payload/attributes |
| SEC-008 | Error handlers on listener-fronted flows | **FAIL** | src/main/mule/test-automation.xml: flow munit-hello-worldFlow has no error-handler; src/main/mule/test-automation.xml: flow user-with-postsFlow has no error-handler |
| SEC-009 | Dependency versions pinned in pom.xml | **PASS** | All dependencies have pinned versions |
| SEC-010 | CI credentials sourced from GitHub secrets | **PASS** | CI credentials sourced from secrets |

Reference: https://docs.mulesoft.com/general/security-best-practices
