package com.github.guoyyit.hsmsimulatorjava.tests;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.file.Path;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class HsmRestErrorTest {

    @TempDir
    static Path tempDir;

    @DynamicPropertySource
    static void dataDir(DynamicPropertyRegistry registry) {
        registry.add("hsm.data-dir", () -> tempDir.resolve("hsm").toString());
    }

    @Autowired
    private MockMvc mockMvc;

    @Test
    void uninitializedTokenReturnsDistinguishableError() throws Exception {
        mockMvc.perform(post("/api/hsm/sessions"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("TOKEN_NOT_INITIALIZED"));
    }
}
