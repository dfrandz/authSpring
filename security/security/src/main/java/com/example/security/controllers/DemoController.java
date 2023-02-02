package com.example.security.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/demo-controller")
public class DemoController {
    @GetMapping
    public ResponseEntity<String> sayHello() {
        return ResponseEntity.ok("Hello from secured endpoint");
    }

    @PostMapping("/add-product")
    public ResponseEntity<String> addProduct(){
        return ResponseEntity.ok("add product");
    }
}
