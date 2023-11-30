package com.leyton.salescope.web;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/process")
public class ProcessingController {

    @PostMapping("/audio")
    public String process(){
        return  "Your file is being processed...";
    }

}
