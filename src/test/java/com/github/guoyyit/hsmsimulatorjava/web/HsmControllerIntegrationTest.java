package com.github.guoyyit.hsmsimulatorjava.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.MethodOrderer;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class HsmControllerIntegrationTest {

    private static final Path DATA_DIR;

    static {
        try {
            DATA_DIR = Files.createTempDirectory("hsm-it-");
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @DynamicPropertySource
    static void dataDir(DynamicPropertyRegistry registry) {
        registry.add("hsm.data.dir", () -> DATA_DIR.toString());
    }

    @Autowired
    private MockMvc mockMvc;

    @Test
    @org.junit.jupiter.api.Order(1)
    void fullTokenWorkflowOverHttp() throws Exception {
        mockMvc.perform(post("/api/hsm/init")
                        .contentType("application/json")
                        .content("{\"soPin\":\"so-pin\",\"userPin\":\"user-pin\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("initialized"));

        mockMvc.perform(post("/api/hsm/init")
                        .contentType("application/json")
                        .content("{\"soPin\":\"so-pin\",\"userPin\":\"user-pin\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("TOKEN_ALREADY_INITIALIZED"));

        String sessionId = openSession();
        mockMvc.perform(post("/api/hsm/sessions/{id}/login", sessionId)
                        .contentType("application/json")
                        .content("{\"role\":\"USER\",\"pin\":\"user-pin\"}"))
                .andExpect(status().isOk());

        String keyId = createKey(sessionId);

        mockMvc.perform(post("/api/hsm/keys/{id}/sign", keyId)
                        .header("X-Session-Id", sessionId)
                        .contentType("application/json")
                        .content("{\"data\":\"aGVsbG8=\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("USAGE_NOT_ALLOWED"));

        String ciphertext = mockMvc.perform(post("/api/hsm/keys/{id}/encrypt", keyId)
                        .header("X-Session-Id", sessionId)
                        .contentType("application/json")
                        .content("{\"data\":\"hello\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString()
                .replaceAll(".*\"ciphertext\":\"([^\"]+)\".*", "$1");

        mockMvc.perform(post("/api/hsm/keys/{id}/decrypt", keyId)
                        .header("X-Session-Id", sessionId)
                        .contentType("application/json")
                        .content("{\"data\":\"" + ciphertext + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").value("hello"));

        mockMvc.perform(delete("/api/hsm/keys/{id}", keyId)
                        .header("X-Session-Id", sessionId))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/hsm/keys/{id}", keyId)
                        .header("X-Session-Id", sessionId))
                .andExpect(status().isNotFound());

        mockMvc.perform(delete("/api/hsm/sessions/{id}", sessionId))
                .andExpect(status().isOk());
    }

    @Test
    @org.junit.jupiter.api.Order(2)
    void lockedTokenRejectsOperationsButAllowsStatusAndUnlock() throws Exception {
        String soSession = openSession();
        mockMvc.perform(post("/api/hsm/sessions/{id}/login", soSession)
                        .contentType("application/json")
                        .content("{\"role\":\"SO\",\"pin\":\"so-pin\"}"))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/hsm/lock/{id}", soSession))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/hsm/status")).andExpect(status().isOk());
        mockMvc.perform(post("/api/hsm/sessions")).andExpect(status().isLocked());
        mockMvc.perform(post("/api/hsm/unlock")
                        .contentType("application/json")
                        .content("{\"role\":\"SO\",\"pin\":\"so-pin\"}"))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/hsm/sessions")).andExpect(status().isOk());
    }

    private String openSession() throws Exception {
        String body = mockMvc.perform(post("/api/hsm/sessions"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return body.replaceAll(".*\"sessionId\":\"([^\"]+)\".*", "$1");
    }

    private String createKey(String sessionId) throws Exception {
        String body = mockMvc.perform(post("/api/hsm/keys")
                        .header("X-Session-Id", sessionId)
                        .contentType("application/json")
                        .content("{\"keyType\":\"AES\",\"label\":\"http-key\","
                                + "\"usages\":[\"ENCRYPT\",\"DECRYPT\"],\"extractable\":true}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return body.replaceAll(".*\"id\":\"([^\"]+)\".*", "$1");
    }
}
