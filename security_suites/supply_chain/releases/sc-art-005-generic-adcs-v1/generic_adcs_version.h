/************************************************************************
** Purpose:
**  Generic ADCS component release-version header.
**
** SC-ART-005 fixture: this is a source-compatible derivative of the
** installed NOS3 Generic ADCS header.  It intentionally changes only the
** release identifier; no control, command, telemetry, or configuration
** behaviour is changed.
*************************************************************************/

#ifndef _GENERIC_ADCS_VERSION_H_
#define _GENERIC_ADCS_VERSION_H_

#define GENERIC_ADCS_MAJOR_VERSION 1
#define GENERIC_ADCS_MINOR_VERSION 0
#define GENERIC_ADCS_REVISION      1
#define GENERIC_ADCS_MISSION_REV   0

/* Signed component-release identity used by the SC-ART-005 evidence. */
#define GENERIC_ADCS_RELEASE_ID "sc-art-005-generic-adcs-1.0.1"

#endif
