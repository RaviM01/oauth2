package org.learning.java.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@Slf4j
public class DeviceController {
    @GetMapping("/activate")
    public String activate(@RequestParam(value = "user_code", required = false) String userCode) {
        log.info("DeviceController -> activate");
        if (userCode != null) {
            return "redirect:/oauth2/device_verification?user_code=" + userCode;
        }
        return "device-activate";
    }

    @GetMapping("/activated")
    public String activated() {
        log.info("DeviceController -> activated");
        return "device-activated";
    }

    @GetMapping(value = "/", params = "success")
    public String success() {
        log.info("DeviceController -> success");
        return "device-activated";
    }
}
