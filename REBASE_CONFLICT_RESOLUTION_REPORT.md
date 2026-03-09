# Rebase Conflict Resolution Report
## Date: 2026-03-09
## Branch: swscale-rebase-v2
## Base: master (206b7ce32 - dated 2026-03-09)

## Summary
Successfully rebased 11 commits from swscale-rebase-work branch onto updated master. Resolved conflicts in 7 files across 3 conflict sets during rebase.

## Branch Information
- **Source Branch**: swscale-rebase-work (backup at swscale-rebase-work-BACKUP)
- **New Branch**: swscale-rebase-v2
- **Upstream Gap**: 761 commits behind upstream/master before rebase
- **Rebase Start**: f96ee2a6d (local master, dated Jan 2025)
- **Rebase Target**: 206b7ce32 (upstream master, dated 2026-03-09)

## Conflict Set 1: First Commit (b10ffa821)
**Commit**: [codec,swscale] allow runtime loading of swscale
**Files Conflicted**: 5 files

### 1. channels/rdpecam/client/camera.h (2 conflicts)
**Conflict A - Lines 105-126**: CameraDeviceStream structure members
- **Upstream (HEAD)**: Old codec-specific members (h264, avContext, avInputPkt, avOutFrame, h264Frame, h264FrameMaxSize, sws, swsWidth, swsHeight)
- **Our changes**: Unified video context (FREERDP_VIDEO_CONTEXT* video)
- **Resolution**: Kept our version (unified video context)
- **Rationale**: This is the core of the swscale runtime loading feature - replacing multiple codec-specific contexts with a single unified video API

**Conflict B - Lines 290-301**: Function signature for ecam_encoder_compress
- **Upstream (HEAD)**: `BYTE** ppDstData, size_t* pDstSize` output parameters
- **Our changes**: `wStream* output` parameter + added ecamToVideoFormat function declaration
- **Resolution**: Kept our version (wStream output + ecamToVideoFormat)
- **Rationale**: New video API uses stream-based output instead of pointer-to-pointer

### 2. channels/rdpecam/client/camera_device_main.c (2 conflicts)
**Conflict A - Lines 134-138**: Buffer capacity check in ecam_dev_prepare_sample_response
- **Upstream (HEAD)**: No capacity check
- **Our changes**: Added `Stream_EnsureRemainingCapacity(stream->sampleRespBuffer, 3)` check
- **Resolution**: Kept our version (with capacity check)
- **Rationale**: Improves safety by validating buffer space before writing

**Conflict B - Lines 198-204**: Return statement in ecam_dev_send_pending
- **Upstream (HEAD)**: Call to `ecam_dev_send_sample_response(dev, streamIndex, encodedSample, encodedSize)`
- **Our changes**: Call to `ecam_channel_write(dev->ecam, stream->hSampleReqChannel, CAM_MSG_ID_SampleResponse, output, FALSE)`
- **Resolution**: Kept our version (ecam_channel_write)
- **Rationale**: New API passes the wStream directly to channel write

### 3. channels/rdpecam/client/encoding.c (5 major conflicts)
**Conflict A - Lines 27-163**: Removed demux_uvcH264 function
- **Upstream (HEAD)**: 137 lines of MJPG H264 demuxing code
- **Our changes**: Function completely removed
- **Resolution**: Removed (kept our version)
- **Rationale**: Old codec-specific code replaced by unified video API

**Conflict B - Lines 226-230**: Return value in ecamToVideoFormat
- **Upstream (HEAD)**: `return AV_PIX_FMT_NONE;`
- **Our changes**: `return FREERDP_VIDEO_FORMAT_NONE;`
- **Resolution**: Kept our version (FREERDP_VIDEO_FORMAT_NONE)
- **Rationale**: Function now returns video API format enum instead of FFmpeg enum

**Conflict C - Lines 234-333**: Removed ecam_sws_* functions, replaced ecam_init_video_context
- **Upstream (HEAD)**: ecam_sws_free, ecam_sws_valid, and complex sws_context initialization (100+ lines)
- **Our changes**: Simple freerdp_video_context_new call (11 lines)
- **Resolution**: Kept our version (unified video context)
- **Rationale**: Swscale handling moved into video API abstraction layer

**Conflict D - Lines 341-606**: Removed H264-specific encoder functions
- **Upstream (HEAD)**: ecam_encoder_compress_h264 (94 lines), ecam_encoder_context_free_h264 (36 lines), ecam_init_mjpeg_decoder (46 lines), ecam_encoder_context_init_h264 (71 lines)
- **Our changes**: All functions removed
- **Resolution**: Removed (kept our version)
- **Rationale**: Replaced by unified video API in ecam_encoder_context_init/compress

**Conflict E - Lines 615-689**: Simplified encoder functions
- **Upstream (HEAD)**: Switch statement calling codec-specific functions
- **Our changes**: Direct call to freerdp_video_sample_convert
- **Resolution**: Kept our version (unified video API)
- **Rationale**: Single video API handles all codec conversions internally

### 4. channels/rdpecam/client/v4l/camera_v4l.c (1 conflict)
**Conflict - Lines 690-697**: Logging camera format
- **Upstream (HEAD)**: Special case for MJPG_H264 format
- **Our changes**: Simplified - no special case
- **Resolution**: Kept our version (simplified)
- **Rationale**: MJPG_H264 special handling removed as part of unified video API

### 5. libfreerdp/codec/color.c (1 conflict)
**Conflict - Lines 1271-1285**: Runtime loading check for swscale
- **Upstream (HEAD)**: Direct call to `sws_getContext`
- **Our changes**: Check `freerdp_swscale_available()` before calling `freerdp_sws_getContext`
- **Resolution**: Kept our version (runtime loading)
- **Rationale**: Core feature - adds runtime loading of swscale library

## Conflict Set 2: Commit 7 (085b62774)
**Commit**: Add rdpecam-utils.h from maintainer's branch
**Files Conflicted**: 1 file (add/add conflict)

### channels/rdpecam/common/rdpecam-utils.h (9 conflicts)
All conflicts were the same pattern:
- **Upstream (HEAD)**: Various instances of `WINPR_C_ARRAY_INIT` macro and `WINPR_ATTR_NODISCARD` attribute
- **Our changes**: `{0}` initialization and removed WINPR_ATTR_NODISCARD
- **Resolution**: Kept our version (C11 compatible)
- **Rationale**:
  - `WINPR_C_ARRAY_INIT` not defined in this codebase version
  - `WINPR_ATTR_NODISCARD` causing parse errors ("data definition has no type or storage class")
  - Ensures C11 compatibility

Specific conflicts resolved:
1. Line 35: `va_list ap` initialization - Changed WINPR_C_ARRAY_INIT → {0}
2. Lines 60-63: Removed WINPR_ATTR_NODISCARD before rdpecam_valid_messageId_
3. Lines 105-108: Removed WINPR_ATTR_NODISCARD before rdpecam_valid_CamErrorCode_
4. Lines 144-147: Removed WINPR_ATTR_NODISCARD before rdpecam_valid_CamStreamFrameSourceType_
5. Lines 177-180: Removed WINPR_ATTR_NODISCARD before rdpecam_valid_CamStreamCategory_
6. Lines 207-210: Removed WINPR_ATTR_NODISCARD before rdpecam_valid_CamMediaFormat_
7. Lines 244-247: Removed WINPR_ATTR_NODISCARD before rdpecam_valid_MediaTypeDescriptionFlags_
8. Lines 303-306: Removed WINPR_ATTR_NODISCARD before rdpecam_valid_CamPropertySet_
9. Lines 334-337: Removed WINPR_ATTR_NODISCARD before rdpecam_valid_CamPropertyCapabilities_

## Conflict Set 3: Commit 9 (5e240defe)
**Commit**: Fix remaining compatibility issues: remove WINPR_ATTR_NODISCARD, update rdpecam.h, add Stream_ResetPosition
**Files Conflicted**: 1 file

### winpr/include/winpr/stream.h (2 conflicts)
**Conflict A - Lines 1348-1359**: Documentation comment for Stream_ResetPosition
- **Upstream (HEAD)**: Detailed doc comment with references
- **Our changes**: Simpler doc comment
- **Resolution**: Kept upstream version (more detailed)
- **Rationale**: Both versions add the same function, upstream's documentation is more complete with cross-references

**Conflict B - Lines 1369-1372**: WINPR_ATTR_NODISCARD before Stream_SetPosition
- **Upstream (HEAD)**: Has WINPR_ATTR_NODISCARD attribute
- **Our changes**: Removed WINPR_ATTR_NODISCARD
- **Resolution**: Kept our version (removed)
- **Rationale**: Consistent with removal pattern for C11 compatibility

## Resolution Strategy Applied
For all conflicts, we consistently applied these principles:
1. **Video API Changes**: Always kept the new unified video API (our version)
2. **C11 Compatibility**: Replaced C23 features (nullptr, WINPR_C_ARRAY_INIT) with C11 equivalents (NULL, {0})
3. **Macro Removal**: Removed WINPR_ATTR_NODISCARD when not defined in codebase
4. **Documentation**: Kept more detailed documentation when available (upstream)
5. **Safety Improvements**: Kept additional safety checks (buffer capacity validation)

## Commits Dropped
- Commit 8 (0b352276e): "Add include_directories(common) to rdpecam CMakeLists.txt"
  - **Reason**: "patch contents already upstream"
  - **Impact**: None - upstream already included this change

## Final Commit Structure (11 → 10 commits)
1. bdbfd1d75 - [codec,swscale] allow runtime loading of swscale
2. 82f604a88 - [temp] fix documentation example to match API
3. 44027b6e0 - [temp] fix C23 nullptr -> NULL for C11 compatibility
4. 780f45079 - Fix freerdp_glyph_convert_ex forward declaration
5. 5586ddc38 - Fix C11 compatibility: remove WINPR_ATTR_NODISCARD, replace nullptr with NULL, replace WINPR_C_ARRAY_INIT
6. 9a5b123e9 - Fix WINPR_ATTR_NODISCARD in camera.h and nullptr/WINPR_C_ARRAY_INIT in all rdpecam files
7. 18b00a13b - Add rdpecam-utils.h from maintainer's branch
8. (dropped)  - Add include_directories(common) to rdpecam CMakeLists.txt
9. 9cf41f8f8 - Fix remaining compatibility issues: remove WINPR_ATTR_NODISCARD, update rdpecam.h, add Stream_ResetPosition
10. fb3dc2171 - Remove unused functions and fix cast warnings in video.c
11. 8de5d50bd - Remove unused is_compressed_format function

## Files Modified During Rebase
- channels/rdpecam/client/camera.h
- channels/rdpecam/client/camera_device_main.c
- channels/rdpecam/client/encoding.c
- channels/rdpecam/client/v4l/camera_v4l.c
- channels/rdpecam/common/rdpecam-utils.h
- libfreerdp/codec/color.c
- winpr/include/winpr/stream.h

## Next Steps
1. ✅ Rebase completed successfully
2. ⏳ Test build on Linux machine with both WITH_SWSCALE_LOADING=ON and OFF
3. ⏳ Verify functionality against original branch (swscale-rebase-work)
4. ⏳ Clean up untracked files (.bak files, test artifacts)
5. ⏳ Squash commits into single commit with original message
6. ⏳ Final review and push to swscale-runtime-loader branch

## Verification Needed
- Build test with WITH_SWSCALE_LOADING=ON
- Build test with WITH_SWSCALE_LOADING=OFF
- Compare behavior with swscale-rebase-work reference branch
- Ensure no swscale-related warnings in build output
