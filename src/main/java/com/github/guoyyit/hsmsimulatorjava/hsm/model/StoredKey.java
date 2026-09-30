package com.github.guoyyit.hsmsimulatorjava.hsm.model;

import java.util.Set;

/**
 * A key object living on the token. Sensitive material is stored only in
 * protected (encrypted) form by the persistence layer.
 */
public class StoredKey {

    private String id;
    private String label;
    private KeyType keyType;
    private int keyBits;
    private Set<KeyUsage> usages;
    private boolean sensitive;
    private boolean extractable;
    private boolean destroyed;
    private long createdAt;

    /**
     * Private/sensitive material protected with the token master key
     * (AES-GCM ciphertext, iv-prefixed). Never leaves the service in plaintext.
     */
    private byte[] protectedMaterial;

    /**
     * Non-sensitive public material for asymmetric keys (X.509-encoded).
     */
    private byte[] publicMaterial;

    public StoredKey() {
    }

    public StoredKey(String id, String label, KeyType keyType, int keyBits,
                     Set<KeyUsage> usages, boolean sensitive, boolean extractable,
                     long createdAt, byte[] protectedMaterial, byte[] publicMaterial) {
        this.id = id;
        this.label = label;
        this.keyType = keyType;
        this.keyBits = keyBits;
        this.usages = usages;
        this.sensitive = sensitive;
        this.extractable = extractable;
        this.createdAt = createdAt;
        this.protectedMaterial = protectedMaterial;
        this.publicMaterial = publicMaterial;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public void setKeyType(KeyType keyType) {
        this.keyType = keyType;
    }

    public void setKeyBits(int keyBits) {
        this.keyBits = keyBits;
    }

    public void setUsages(Set<KeyUsage> usages) {
        this.usages = usages;
    }

    public void setSensitive(boolean sensitive) {
        this.sensitive = sensitive;
    }

    public void setExtractable(boolean extractable) {
        this.extractable = extractable;
    }

    public void markDestroyed() {
        this.destroyed = true;
        this.protectedMaterial = null;
        this.publicMaterial = null;
        this.usages = Set.of();
    }

    public void setDestroyed(boolean destroyed) {
        this.destroyed = destroyed;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    public void setProtectedMaterial(byte[] protectedMaterial) {
        this.protectedMaterial = protectedMaterial;
    }

    public void setPublicMaterial(byte[] publicMaterial) {
        this.publicMaterial = publicMaterial;
    }

    public String getId() {
        return id;
    }

    public String getLabel() {
        return label;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public int getKeyBits() {
        return keyBits;
    }

    public Set<KeyUsage> getUsages() {
        return usages;
    }

    public boolean allows(KeyUsage usage) {
        return usages != null && usages.contains(usage);
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public byte[] getProtectedMaterial() {
        return protectedMaterial;
    }

    public byte[] getPublicMaterial() {
        return publicMaterial;
    }

    public boolean isSensitive() {
        return sensitive;
    }

    public boolean isExtractable() {
        return extractable;
    }

    public boolean isDestroyed() {
        return destroyed;
    }
}
