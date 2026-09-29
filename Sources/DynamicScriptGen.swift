import UIKit

/// 根据静态分析证据生成「可直接执行的动态分析脚本包」。
/// 真实动态分析需在越狱设备 + frida-server，或电脑端 mitmproxy/Appium 执行；
/// 本模块把这些工具链的脚本自动生成好，供用户一键导出即跑。
enum DynamicScriptGen {

    // MARK: - Frida ObjC Hook 脚本（越狱设备 + frida -U -l hook.js）

    static func fridaScript(_ r: AnalysisResult) -> String {
        var s = "/* IPAInspect 动态分析 · 自动生成的 Frida ObjC Hook 脚本 */\n"
        s += "/* 用法: 越狱设备启动 frida-server 后执行  frida -U -l hook.js <App 名>  */\n"
        s += "var logPath = '/data/local/tmp/ipa-hooks.log';\n"
        s += "function logLine(m){ var line = '[' + new Date().toISOString() + '] ' + m + '\\n'; "
        s += "console.log(line.trim()); try{ var f = new File(logPath, 'a'); f.write(line); f.close(); }catch(e){} }\n"
        s += "function hook(c, sel, tag){ try{ var cls = ObjC.classes[c]; if(!cls) return; "
        s += "var m = cls[sel]; if(!m) return; "
        s += "Interceptor.attach(m.implementation, { onEnter:function(a){ logLine(tag + ' ' + c + ' ' + sel); } }); "
        s += "logLine('hooked ' + c + ' ' + sel); }catch(e){ logLine('hook fail ' + c + ' ' + sel); } }\n\n"

        s += "/* ---- 网络 / 数据外传 ---- */\n"
        s += "hook('NSURLSession', '-dataTaskWithRequest:completionHandler:', 'NET');\n"
        s += "hook('NSURLSession', '-dataTaskWithURL:', 'NET');\n"
        s += "hook('NSURLConnection', '-sendSynchronousRequest:', 'NET');\n"
        s += "hook('NSURLConnection', '-initWithRequest:delegate:', 'NET');\n"
        s += "hook('NSURLSession', '-uploadTaskWithRequest:fromData:', 'UPLOAD');\n\n"

        var sec = [String]()
        for p in r.plist.permissions {
            switch p.key {
            case "NSCameraUsageDescription": sec.append("hook('AVCaptureSession', '-startRunning', 'CAM');")
            case "NSMicrophoneUsageDescription": sec.append("hook('AVAudioRecorder', '-record', 'MIC');")
            case "NSPhotoLibraryUsageDescription": sec.append("hook('PHPhotoLibrary', '+requestAuthorization', 'PHOTO');")
            case "NSContactsUsageDescription": sec.append("hook('CNContactStore', '-fetchUnifiedContactsWithPredicate:keysToFetch:sortOrder:', 'CONTACTS');")
            case "NSLocationAlwaysUsageDescription", "NSLocationWhenInUseUsageDescription":
                sec.append("hook('CLLocationManager', '-startUpdatingLocation', 'LOC');")
            case "NSLocalNetworkUsageDescription": sec.append("hook('NWBrowser', '-start', 'LAN');")
            default: break
            }
        }
        if !sec.isEmpty {
            s += "/* ---- 隐私权限对应系统 API ---- */\n" + sec.joined(separator: "\n") + "\n\n"
        }

        s += "/* ---- 文件落盘 ---- */\n"
        s += "hook('NSFileManager', '-writeToFile:atomically:', 'FILE');\n"
        s += "hook('NSFileManager', '-createFileAtPath:contents:attributes:', 'FILE');\n\n"

        s += "/* 抓包建议: 另开终端运行  mitmproxy -s mitm_filter.py 并让设备走代理 */\n"
        s += "/* 若需 Hook 指定方法, 在此追加 hook('类名','-方法名:','TAG'); */\n"
        return s
    }

    // MARK: - Appium 自动化测试骨架（电脑端 pytest + Appium）

    static func appiumScript(_ r: AnalysisResult) -> String {
        let capsName = r.plist.displayName.isEmpty ? r.fileName : r.plist.displayName
        var s = "# IPAInspect 动态分析 · 自动生成的 Appium UI 自动化骨架\n"
        s += "# 依赖: pip install Appium-Python-Client pytest\n"
        s += "import time\nimport pytest\nfrom appium import webdriver\nfrom appium.webdriver.common.touch_action import TouchAction\n\n"
        s += "CAPS = {\n"
        s += "    'platformName': 'iOS',\n"
        s += "    'automationName': 'XCUITest',\n"
        s += "    'deviceName': 'iPhone',\n"
        s += "    'bundleId': '\(r.plist.bundleID.isEmpty ? "com.example.app" : r.plist.bundleID)',\n"
        s += "    'noReset': False,\n"
        s += "}\n\n"
        s += "@pytest.fixture(scope='session')\n"
        s += "def driver():\n"
        s += "    d = webdriver.Remote('http://localhost:4723/wd/hub', CAPS)\n"
        s += "    yield d\n"
        s += "    d.quit()\n\n"
        s += "def test_launch_and_grant(driver):\n"
        s += "    # 冷启动, 观察首屏\n"
        s += "    driver.launch_app()\n"
        s += "    time.sleep(3)\n"
        s += "    driver.save_screenshot('/tmp/ipa-01-launch.png')\n"
        s += "    # 授予弹窗权限 (iOS 15+ XCUITest 弹窗)\n"
        s += "    for btn in ['Allow', '允许', '好']:\n"
        s += "        els = driver.find_elements('name', btn)\n"
        s += "        if els:\n"
        s += "            els[0].click()\n"
        s += "            break\n\n"
        s += "def test_trigger_privacy_flows(driver):\n"
        s += "    # 触发登录/注册、拍照、定位等入口, 结合 frida 日志验证是否回传\n"
        s += "    driver.tap([(200, 400)])\n"
        s += "    time.sleep(2)\n"
        s += "    driver.save_screenshot('/tmp/ipa-02-flow.png')\n\n"
        s += "def test_background_resume(driver):\n"
        s += "    driver.background_app(5)\n"
        s += "    driver.launch_app()\n"
        s += "    time.sleep(2)\n"
        s += "    # 检查 frida 日志是否出现后台仍在上传\n"
        return s
    }

    // MARK: - mitmproxy 抓包过滤器（电脑端）

    static func mitmScript(_ r: AnalysisResult) -> String {
        var s = "# IPAInspect 动态分析 · mitmproxy 过滤器/记录器\n"
        s += "# 用法:  mitmproxy -s mitm_filter.py   设备走该代理\n"
        s += "import json\n\n"
        s += "ALERT_HOSTS = {\n"
        for u in r.urls.prefix(60) {
            if u.kind == "domain" || u.kind == "ip" {
                s += "    '\(u.url)': '\(u.suspicious ? "suspicious" : "normal")',\n"
            }
        }
        s += "}\n"
        s += "SECRETS = [\n"
        for c in (r.credentials ?? []).prefix(40) {
            s += "    '\(c.text.prefix(60))',\n"
        }
        s += "]\n\n"
        s += "def request(flow):\n"
        s += "    host = flow.request.pretty_host\n"
        s += "    tag = ALERT_HOSTS.get(host)\n"
        s += "    if tag:\n"
        s += "        print('[IPA][{}] {} {}'.format(tag, flow.request.method, flow.request.url))\n"
        s += "    body = flow.request.get_text() or ''\n"
        s += "    for sec in SECRETS:\n"
        s += "        if sec and sec in body:\n"
        s += "            print('[IPA][LEAK] 凭据随请求外传 -> ' + flow.request.url)\n"
        s += "    flow.addon.log(\"{} {}\".format(flow.request.method, flow.request.url))\n"
        return s
    }

    // MARK: - 编排 shell（一键启动整套动态分析）

    static func orchestration(_ r: AnalysisResult) -> String {
        var s = "#!/bin/bash\n"
        s += "# IPAInspect 动态分析编排 · 电脑端一键启动\n"
        s += "# 1) 越狱设备启动 frida-server   2) 本机跑此脚本\n"
        s += "set -e\n"
        s += "APP_NAME='\(r.plist.displayName.isEmpty ? "app" : r.plist.displayName)'\n"
        s += "echo '[1/3] 启动 mitmproxy ...'\n"
        s += "mitmproxy -s mitm_filter.py &\n"
        s += "MITM_PID=$!\n"
        s += "echo '[2/3] 启动 frida hook (越狱设备) ...'\n"
        s += "frida -U -l hook.js \"$APP_NAME\" --no-pause &\n"
        s += "FRIDA_PID=$!\n"
        s += "sleep 2\n"
        s += "echo '[3/3] 运行 Appium 自动化 ...'\n"
        s += "pytest -s test_dynamic.py\n"
        s += "echo '分析结束, 结果见 /tmp/ipa-*.png 与 /data/local/tmp/ipa-hooks.log'\n"
        s += "kill $MITM_PID $FRIDA_PID 2>/dev/null || true\n"
        return s
    }

    // MARK: - 捆绑说明

    static func readme(_ r: AnalysisResult) -> String {
        var s = "# IPAInspect 动态分析脚本包\n\n"
        s += "根据样本静态证据自动生成，用于在越狱设备/电脑端执行真实动态分析。\n\n"
        s += "## 文件\n"
        s += "- hook.js          Frida ObjC Hook（网络/相机/麦克风/通讯录/定位/局域网/落盘）\n"
        s += "- test_dynamic.py  Appium UI 自动化骨架（启动/授权/触发/后台）\n"
        s += "- mitm_filter.py   mitmproxy 过滤器（标记外联 + 检测凭据外传）\n"
        s += "- run_dynamic.sh   一键编排脚本\n\n"
        s += "## 步骤\n"
        s += "1. 越狱设备启动 frida-server\n"
        s += "2. 电脑: mitmproxy + Appium(4723) 就绪\n"
        s += "3. bash run_dynamic.sh\n\n"
        s += "## 免责声明\n"
        s += "仅用于合法授权样本的安全研究与学习，禁止用于逆向破解、恶意分析或任何违法行为。\n"
        return s
    }

    // MARK: - 导出脚本包（写入临时目录并返回文件 URL 列表，供 UIActivityViewController 分享）

    static func exportBundle(_ r: AnalysisResult, into dir: URL) -> [URL] {
        let fm = FileManager.default
        let files: [(String, String)] = [
            ("hook.js", fridaScript(r)),
            ("test_dynamic.py", appiumScript(r)),
            ("mitm_filter.py", mitmScript(r)),
            ("run_dynamic.sh", orchestration(r)),
            ("README.txt", readme(r))
        ]
        var urls: [URL] = []
        for (name, content) in files {
            let url = dir.appendingPathComponent(name)
            try? content.write(to: url, atomically: true, encoding: .utf8)
            urls.append(url)
        }
        _ = fm  // keep
        return urls
    }
}
