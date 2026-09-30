package com.github.guoyyit.hsmsimulatorjava.tests;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.file.Path;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class HsmRestFlowTest {

    @TempDir
    static Path tempDir;

    @DynamicPropertySource
    static void dataDir(DynamicPropertyRegistry registry) {
        registry.add("hsm.data-dir", () -> tempDir.resolve("hsm").toString());
    }

    @Autowired
    private MockMvc mockMvc;

    @Test
    void endToEndRestFlow() throws Exception {
        mockMvc.perform(post("/api/hsm/initialize")
                        .contentType("application/json")
                        .content("{\"soPin\":\"so-pin\",\"userPin\":\"user-pin\",\"label\":\"rest\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.initialized").value(true));

        MvcResult sessionResult = mockMvc.perform(post("/api/hsm/sessions"))
                .andExpect(status().isOk())
                .andReturn();
        long handle = Long.parseLong(sessionResult.getResponse().getContentAsString()
                .replaceAll("\\D+", ""));

        mockMvc.perform(post("/api/hsm/sessions/" + handle + "/login")
                        .contentType("application/json")
                        .content("{\"role\":\"USER\",\"pin\":\"user-pin\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("USER"));

        MvcResult keyResult = mockMvc.perform(post("/api/hsm/keys/generate")
                        .contentType("application/json")
                        .content("{\"sessionHandle\":" + handle
                                + ",\"keyType\":\"AES\",\"bits\":128,\"label\":\"web\""
                                + ",\"usages\":[\"ENCRYPT\",\"DECRYPT\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keyType").value("AES"))
                .andExpect(jsonPath("$.sensitive").value(true))
                .andReturn();
        String keyId = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(keyResult.getResponse().getContentAsString()).get("id").asText();

        mockMvc.perform(post("/api/hsm/encrypt")
                        .contentType("application/json")
                        .content("{\"sessionHandle\":" + handle + ",\"keyId\":\"" + keyId
                                + "\",\"data\":\"aGVsbG8=\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ciphertext").exists());

        mockMvc.perform(get("/api/hsm/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keyCount").value(1));
    }
}
