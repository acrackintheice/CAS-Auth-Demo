package hello.controller;

import hello.model.Greeting;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Created by eduardo on 12/07/17.
 */

@CrossOrigin
@org.springframework.web.bind.annotation.RestController
public class RestController {

    @RequestMapping("/api/greeting")
    public Greeting greeting(@RequestParam(value="name", required=false, defaultValue="Rest") String name) {
        return new Greeting("Hello, " + name);
    }
}
