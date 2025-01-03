package ar.dev.maxisandoval.auth2clientapp.controllers;

import ar.dev.maxisandoval.auth2clientapp.models.Message;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController
@Slf4j
public class BasicController {

    @GetMapping("/listMessages")
    public List<Message> listMessages() {
        log.info("Enter to: listMessages");
        return Collections.singletonList(new Message("Test"));
    }

    @PostMapping("/createMessage")
    public Message createMessage(@RequestBody Message message) {
        log.info("Message saved: ".concat(message.getText()));
        return message;
    }

    @GetMapping("/authorized")
    public Map<String, String> authorized(@RequestParam String code) {
        // jwt.io -> ver datos del token
        log.info("Authorized code token: ".concat(code));
        return Collections.singletonMap("code", code);
    }

}