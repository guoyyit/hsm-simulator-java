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
import java.util.Base64;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * REST-level checks for the tightened role rules, the extractable attribute
 * and the close-all-sessions entry point.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class HsmRestSecurityTest {

    @TempDir
    static Path tempDir;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @DynamicPropertySource
    static void dataDir(DynamicPropertyRegistry registry) {
        registry.add("hsm.data-dir", () -> tempDir.resolve("hsm").toString());
    }

    @Autowired
    private MockMvc mockMvc;

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

    private String generateKey(long handle, boolean extractable) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/hsm/keys/generate")
                        .contentType("application/json")
                        .content("{\"sessionHandle\":" + handle
                                + ",\"keyType\":\"AES\",\"bits\":128,\"label\":\"k\""
                                + ",\"usages\":[\"WRAP\",\"UNWRAP\",\"ENCRYPT\",\"DECRYPT\"]"
                                + ",\"extractable\":" + extractable + "}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.extractable").value(extractable))
                .andReturn();
        return MAPPER.readTree(result.getResponse().getContentAsString()).get("id").asText();
    }

    @Test
    @Order(1)
    void soSessionIsRejectedWithRoleRequiredOverRest() throws Exception {
        mockMvc.perform(post("/api/hsm/initialize")
                        .contentType("application/json")
                        .content("{\"soPin\":\"so-pin\",\"userPin\":\"user-pin\",\"label\":\"rest\"}"))
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
                        .content("{\"sessionHandle\":" + so
                                + ",\"data\":\"aGVsbG8=\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("ROLE_REQUIRED"));

        // Management operations stay available to the SO session.
        mockMvc.perform(post("/api/hsm/lock")
                        .contentType("application/json")
                        .content("{\"sessionHandle\":" + so + "}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.locked").value(true));
        mockMvc.perform(post("/api/hsm/unlock")
                        .contentType("application/json")
                        .content("{\"soPin\":\"so-pin\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.locked").value(false));
    }

    @Test
    @Order(2)
    void nonExtractableKeyWrapIsRejectedWithDistinguishableError() throws Exception {
        long user = openSession();
        login(user, "USER", "user-pin");
        String kekId = generateKey(user, true);
        String sealedId = generateKey(user, false);

        // Default (field absent) stays non-extractable for old clients.
        MvcResult defaulted = mockMvc.perform(post("/api/hsm/keys/generate")
                        .contentType("application/json")
                        .content("{\"sessionHandle\":" + user
                                + ",\"keyType\":\"AES\",\"bits\":128,\"label\":\"legacy\""
                                + ",\"usages\":[\"ENCRYPT\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.extractable").value(false))
                .andReturn();
        String legacyId = MAPPER.readTree(defaulted.getResponse().getContentAsString())
                .get("id").asText();

        for (String target : new String[]{sealedId, legacyId}) {
            mockMvc.perform(post("/api/hsm/keys/wrap")
                            .contentType("application/json")
                            .content("{\"sessionHandle\":" + user
                                    + ",\"wrappingKeyId\":\"" + kekId
                                    + "\",\"targetKeyId\":\"" + target + "\"}"))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.error").value("KEY_NOT_EXTRACTABLE"));
        }

        // An extractable key wraps fine and the copy keeps the attribute.
        String openId = generateKey(user, true);
        MvcResult wrapped = mockMvc.perform(post("/api/hsm/keys/wrap")
                        .contentType("application/json")
                        .content("{\"sessionHandle\":" + user
                                + ",\"wrappingKeyId\":\"" + kekId
                                + "\",\"targetKeyId\":\"" + openId + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String blob = MAPPER.readTree(wrapped.getResponse().getContentAsString())
                .get("wrapped").asText();
        mockMvc.perform(post("/api/hsm/keys/unwrap")
                        .contentType("application/json")
                        .content("{\"sessionHandle\":" + user
                                + ",\"wrappingKeyId\":\"" + kekId
                                + "\",\"wrapped\":\"" + blob + "\""
                                + ",\"usages\":[\"WRAP\",\"UNWRAP\",\"ENCRYPT\",\"DECRYPT\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.extractable").value(true));
    }

    @Test
    @Order(3)
    void closeAllSessionsEndpointInvalidatesEveryHandle() throws Exception {
        long first = openSession();
        long second = openSession();
        login(first, "USER", "user-pin");
        login(second, "USER", "user-pin");

        mockMvc.perform(delete("/api/hsm/sessions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.closedAll").value(true));

        for (long handle : new long[]{first, second}) {
            mockMvc.perform(get("/api/hsm/sessions/" + handle))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.error").value("SESSION_HANDLE_INVALID"));
        }

        // Token state is untouched and fresh sessions work immediately.
        mockMvc.perform(get("/api/hsm/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.locked").value(false))
                .andExpect(jsonPath("$.openSessions").value(0));
        long fresh = openSession();
        login(fresh, "USER", "user-pin");
        mockMvc.perform(post("/api/hsm/digest")
                        .contentType("application/json")
                        .content("{\"sessionHandle\":" + fresh
                                + ",\"data\":\"" + Base64.getEncoder().encodeToString("x".getBytes())
                                + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.digest").exists());
    }

    @Test
    @Order(4)
    void singleSessionCloseDoesNotDisturbOthers() throws Exception {
        long first = openSession();
        long second = openSession();
        login(first, "USER", "user-pin");
        login(second, "USER", "user-pin");

        mockMvc.perform(delete("/api/hsm/sessions/" + first))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/hsm/sessions/" + first))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/hsm/sessions/" + second))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("USER"));
    }
}
