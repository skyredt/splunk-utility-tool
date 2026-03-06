# 🎯 Quick Testing Reference Card

**Status**: ✅ TOOL READY FOR TESTING  
**Date**: February 13, 2026  
**Version**: 3.0.2

---

## ✅ Pre-Testing Checklist (Already Done)

```
[x] Code implemented and validated
[x] Configuration created and tested
[x] Documentation complete (2,000+ lines)
[x] Tool starts successfully
[x] Splunk connection established
[x] All imports verified
[x] Syntax validation passed
```

---

## 🧪 Testing Quick Start

### What You Need
- Tool: Running in terminal (python main.py) ✅
- Config: config.ini with Splunk credentials ✅
- Splunk: Accessible at https://127.0.0.1:8089 ✅
- Terminal: Open and monitoring (see output) ✅

### What To Look For

#### Phase 1: MergeReport (If Enabled)
```
✅ Monitor started for mergeReport_alert.log
✅ Real-time log lines appear
✅ Metadata extracted (Action, Size, etc.)
```

#### Phase 2: POST-DISPATCH (Recommended - Enabled by Default)
```
✅ [PostDispatch] Monitor started
✅ [PostDispatch] [MergeReport] (sid=...) lines appear
✅ [PostDispatch] [NativeEmail] (sid=...) lines appear
✅ Final summary shows counts
```

---

## 📋 Test Cases (Quick)

### Test 1: Connection
```
Action: Click "Connect" button
Expect: Connection status updates, apps load
Time: ~10 seconds
```

### Test 2: Load Reports
```
Action: Select app, verify reports appear
Expect: Report list populates (20+ items typical)
Time: ~5 seconds
```

### Test 3: Send Test Report
```
Action: Select 1 report, click "Send reports"
Expect: Dispatch starts, log updates, [PostDispatch] lines appear
Time: ~30-120 seconds
```

### Test 4: Verify POST-DISPATCH
```
Action: Wait for dispatch to complete
Expect: [PostDispatch] lines with status
Expect: Final summary with counts at end
Time: Last 10-30 seconds of dispatch
```

---

## 🔍 What You'll See

### Good Output Example
```
[PostDispatch] Monitor started for REST-based verification
[PostDispatch] [MergeReport] (sid=1699999999_ABC123) SUCCESS: Email sent
[PostDispatch] [NativeEmail] (sid=1700000000_XYZ789) SUCCESS: Email action invoked

=== Post-Dispatch Verification Summary ===
Dispatch OK: 2
Verified Sent: 2
Failed: 0
Unknown: 0
```

### Expected Warnings (Safe to Ignore)
```
InsecureRequestWarning: Unverified HTTPS request is being made
(This is normal for lab environment with self-signed certificates)
```

### Problems (If You See These)
```
❌ Connection refused → Check Splunk is running
❌ Configuration error → Check config.ini format
❌ Import error → Check Python dependencies installed
❌ Thread crash → Check tool logs for error details
```

---

## 🚀 Fast Test (5 minutes)

1. **Verify Running** (Already done ✅)
   ```
   Tool output shows HTTPS warnings → Good ✅
   ```

2. **Test Connection** (1 minute)
   - Click "Connect"
   - Should see app list

3. **Send Test Report** (3-4 minutes)
   - Select 1 report
   - Click "Send reports"
   - Watch for [PostDispatch] lines
   - Verify summary appears

---

## 📊 Full Test (30 minutes)

1. Basic functionality (5 min)
   - Connect ✓
   - Load reports ✓
   - Select multiple reports ✓

2. Dispatch process (15 min)
   - Send 2-3 reports ✓
   - Monitor [PostDispatch] output ✓
   - Verify final summary ✓

3. Error handling (5 min)
   - Try invalid dates ✓
   - Test connection errors ✓

4. Documentation (5 min)
   - Review log output ✓
   - Verify counts make sense ✓

---

## 🎯 Key Success Metrics

| Item | Target | Status |
|------|--------|--------|
| Tool Starts | No errors | ✅ Confirmed |
| Connection | Connects to Splunk | ✅ Confirmed |
| Dispatch | Completes without crashes | ⏳ Pending test |
| [PostDispatch] Output | Lines appear during dispatch | ⏳ Pending test |
| Final Summary | Appears at end | ⏳ Pending test |
| Counts | Dispatch OK ≥ Verified Sent | ⏳ Pending test |

---

## 🔧 Configuration Reference

### Current config.ini
```ini
[postdispatch]
merge_report_enabled = true          ← Monitors MergeReport logs
native_email_enabled = true          ← Monitors sendemail
poll_seconds = 3                     ← Check every 3 sec
lookback_seconds = 300               ← Search last 5 min
```

### To Disable Phase 2
```ini
[postdispatch]
merge_report_enabled = false
native_email_enabled = false
```

---

## 💡 Tips for Testing

1. **Start with 1 report** - Less complex, easier to debug
2. **Watch the log closely** - [PostDispatch] lines appear in real-time
3. **Wait for summary** - Final counts appear at the very end
4. **Check terminal output** - Tool running terminal shows HTTPS requests
5. **Keep config.ini open** - Easy reference for settings

---

## ❓ Quick Troubleshooting

### No [PostDispatch] lines?
```
✓ Check config.ini has [postdispatch] section
✓ Check merge_report_enabled and native_email_enabled = true
✓ Check Splunk actually sent the reports
✓ Wait longer - may take 30+ seconds
```

### Tool Crashes?
```
✓ Check Python 3.9+ installed
✓ Check all modules: python -m py_compile *.py
✓ Check config.ini format (INI syntax)
✓ Check file paths exist
```

### Can't Connect to Splunk?
```
✓ Check Splunk is running: curl https://127.0.0.1:8089
✓ Check username/password in config.ini
✓ Check server URL in config.ini
✓ Try connecting from terminal separately
```

---

## 📞 Need Help?

1. **TESTING_GUIDE.md** - Full test procedures
2. **PHASE_2_DEPLOYMENT.md** - Technical details
3. **QUICK_START_PHASE_2.md** - User reference
4. **Tool log output** - Check for [PostDispatch] errors

---

## ✨ Expected Flow

```
Start Tool
    ↓
Connect to Splunk ← Test 1
    ↓
Load Reports ← Test 2
    ↓
Select Reports
    ↓
Click "Send reports" ← Test 3
    ↓
MergeReport Monitor Starts (if enabled)
    ↓
PostDispatch Monitor Starts ✅
    ↓
[PostDispatch] lines appear ← Test 4
    ↓
Dispatch Completes
    ↓
Final Summary Appears ← Test 5
    ↓
✅ SUCCESS
```

---

## 🎉 Ready?

Tool is **running** ✅  
Config is **ready** ✅  
Documentation is **complete** ✅  

**Start testing!** 🚀

---

**Terminal Running**: 7adc3f09-cfbc-4d02-958b-83a38fc4ffbb  
**Tool Process**: python main.py (ACTIVE)  
**Test Status**: READY TO BEGIN

