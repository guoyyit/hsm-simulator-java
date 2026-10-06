package com.github.guoyyit.hsmsimulatorjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.file.Path;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * REST-level coverage of the tightened role rules, the extractable flag and
 * the one-shot session cleanup endpoint.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class HsmRestAccessAndCleanupTest {

    @TempDir
    static Path tempDir;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @DynamicPropertySource
    static void dataDir(DynamicPropertyRegistry registry) {
        registry.add("hsm.data-dir", () -> tempDir.resolve("hsm").toString());
    }

    @Autowired
    private MockMvc mockMvc;

    @Test
    @Order(1)
    void soSessionIsRejectedFromKeyGenerationWithRoleRequired() throws Exception {
        mockMvc.perform(post("/api/hsm/initialize")
                        .contentType("application/json")
                        .content("{\"soPin\":\"so-pin\",\"userPin\":\"user-pin\",\"label\":\"rest-roles\"}"))
                .andExpect(status().isOk());

        long so = openSession();
        login(so, "SO", "so-pin");

        mockMvc.perform(post("/api/hsm/keys/generate")
                        .contentType("application/json")
                        .content("{\"sessionHandle\":" + so
                                + ",\"keyType\":\"AES\",\"bits\":128,\"label\":\"x\""
                                + ",\"usages\":[\"ENCRYPT\"]}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("ROLE_REQUIRED"));

        mockMvc.perform(post("/api/hsm/digest")
                        .contentType("application/json")
                        .content("{\"sessionHandle\":" + so + ",\"data\":\"aGk=\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("ROLE_REQUIRED"));
    }

    @Test
    @Order(2)
    void extractableFlagFlowsThroughRestAndWrapEnforcesIt() throws Exception {
        long user = openSession();
        login(user, "USER", "user-pin");

        String kek = generate(user, null, "[\"WRAP\",\"UNWRAP\"]");
        String sealed = generate(user, false, "[\"ENCRYPT\",\"DECRYPT\"]");
        String open = generate(user, true, "[\"ENCRYPT\",\"DECRYPT\"]");

        mockMvc.perform(get("/api/hsm/keys/" + sealed + "?sessionHandle=" + user))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.extractable").value(false));
        mockMvc.perform(get("/api/hsm/keys/" + open + "?sessionHandle=" + user))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.extractable").value(true));

        mockMvc.perform(post("/api/hsm/keys/wrap")
                        .contentType("application/json")
                        .content("{\"sessionHandle\":" + user + ",\"wrappingKeyId\":\"" + kek
                                + "\",\"targetKeyId\":\"" + sealed + "\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("KEY_NOT_EXTRACTABLE"));

        MvcResult wrapped = mockMvc.perform(post("/api/hsm/keys/wrap")
                        .contentType("application/json")
                        .content("{\"sessionHandle\":" + user + ",\"wrappingKeyId\":\"" + kek
                                + "\",\"targetKeyId\":\"" + open + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String blob = MAPPER.readTree(wrapped.getResponse().getContentAsString())
                .get("wrapped").asText();

        mockMvc.perform(post("/api/hsm/keys/unwrap")
                        .contentType("application/json")
                        .content("{\"sessionHandle\":" + user + ",\"wrappingKeyId\":\"" + kek
                                + "\",\"wrapped\":\"" + blob + "\",\"label\":\"copy\""
                                + ",\"usages\":[\"ENCRYPT\",\"DECRYPT\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.extractable").value(true));
    }

    @Test
    @Order(3)
    void deleteSessionsEndpointInvalidatesAllHandles() throws Exception {
        long first = openSession();
        long second = openSession();
        login(first, "USER", "user-pin");

        mockMvc.perform(delete("/api/hsm/sessions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.closedAll").value(true));

        mockMvc.perform(get("/api/hsm/sessions/" + first))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("SESSION_HANDLE_INVALID"));
        mockMvc.perform(get("/api/hsm/sessions/" + second))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("SESSION_HANDLE_INVALID"));

        // Token state is untouched and a fresh session logs in normally.
        mockMvc.perform(get("/api/hsm/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.initialized").value(true))
                .andExpect(jsonPath("$.locked").value(false));

        long fresh = openSession();
        login(fresh, "USER", "user-pin");
        mockMvc.perform(post("/api/hsm/digest")
                        .contentType("application/json")
                        .content("{\"sessionHandle\":" + fresh + ",\"data\":\"aGk=\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.digest").exists());
    }

    private long openSession() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/hsm/sessions"))
                .andExpect(status().isOk())
                .andReturn();
        return MAPPER.readTree(result.getResponse().getContentAsString())
                .get("sessionHandle").asLong();
    }

    private void login(long handle, String role, String pin) throws Exception {
        mockMvc.perform(post("/api/hsm/sessions/" + handle + "/login")
                        .contentType("application/json")
                        .content("{\"role\":\"" + role + "\",\"pin\":\"" + pin + "\"}"))
                .andExpect(status().isOk());
    }

    private String generate(long session, Boolean extractable, String usages) throws Exception {
        String extractableField = extractable == null ? ""
                : ",\"extractable\":" + extractable;
        MvcResult result = mockMvc.perform(post("/api/hsm/keys/generate")
                        .contentType("application/json")
                        .content("{\"sessionHandle\":" + session
                                + ",\"keyType\":\"AES\",\"bits\":256,\"label\":\"k\""
                                + ",\"usages\":" + usages + extractableField + "}"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode node = MAPPER.readTree(result.getResponse().getContentAsString());
        if (extractable != null) {
            org.junit.jupiter.api.Assertions.assertEquals(
                    extractable, node.get("extractable").asBoolean());
        }
        return node.get("id").asText();
    }
}
