/****************************************************************************
**
** Copyright (C) 2016 The Qt Company Ltd.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the QtGui module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 3 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL3 included in the
** packaging of this file. Please review the following information to
** ensure the GNU Lesser General Public License version 3 requirements
** will be met: https://www.gnu.org/licenses/lgpl-3.0.html.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 2.0 or (at your option) the GNU General
** Public license version 3 or any later version approved by the KDE Free
** Qt Foundation. The licenses are as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL2 and LICENSE.GPL3
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-2.0.html and
** https://www.gnu.org/licenses/gpl-3.0.html.
**
** $QT_END_LICENSE$
**
****************************************************************************/

#include "qhighdpiscaling_p.h"
#include "qguiapplication.h"
#include "qscreen.h"
#include "qplatformintegration.h"
#include "qplatformwindow.h"
#include "private/qscreen_p.h"
#include <private/qguiapplication_p.h>

#include <QtCore/qdebug.h>
#include <QtCore/qmetaobject.h>

#include <algorithm>

QT_BEGIN_NAMESPACE

Q_LOGGING_CATEGORY(lcScaling, "qt.scaling");

#ifndef QT_NO_HIGHDPISCALING

static const char enableHighDpiScalingEnvVar[] = "QT_ENABLE_HIGHDPI_SCALING";
static const char scaleFactorEnvVar[] = "QT_SCALE_FACTOR";
static const char screenFactorsEnvVar[] = "QT_SCREEN_SCALE_FACTORS";
static const char scaleFactorRoundingPolicyEnvVar[] = "QT_SCALE_FACTOR_ROUNDING_POLICY";
static const char dpiAdjustmentPolicyEnvVar[] = "QT_DPI_ADJUSTMENT_POLICY";
static const char usePhysicalDpiEnvVar[] = "QT_USE_PHYSICAL_DPI";

// Per-screen scale factors for named screens set with QT_SCREEN_SCALE_FACTORS
// are stored here. Use a global hash to keep the factor across screen
// disconnect/connect cycles where the screen object may be deleted.
typedef QHash<QString, qreal> QScreenScaleFactorHash;
Q_GLOBAL_STATIC(QScreenScaleFactorHash, qNamedScreenScaleFactors);

// Reads and interprets the given environment variable as a bool,
// returns the default value if not set.
static bool qEnvironmentVariableAsBool(const char *name, bool defaultValue)
{
    bool ok = false;
    int value = qEnvironmentVariableIntValue(name, &ok);
    return ok ? value > 0 : defaultValue;
}

static inline qreal initialGlobalScaleFactor()
{

    qreal result = 1;
    if (qEnvironmentVariableIsSet(scaleFactorEnvVar)) {
        bool ok;
        const qreal f = qEnvironmentVariable(scaleFactorEnvVar).toDouble(&ok);
        if (ok && f > 0) {
            qCDebug(lcScaling) << "Apply " << scaleFactorEnvVar << f;
            result = f;
        }
    }

    return result;
}

/*!
    \class QHighDpiScaling
    \since 5.6
    \internal
    \preliminary
    \ingroup qpa

    \brief Collection of utility functions for UI scaling.

    QHighDpiScaling implements utility functions for high-dpi scaling for use
    on operating systems that provide limited support for native scaling, such
    as Windows, X11, and Android. In addition this functionality can be used
    for simulation and testing purposes.

    The functions support scaling between the device independent coordinate
    system used by Qt applications and the native coordinate system used by
    the platform plugins. Intended usage locations are the low level / platform
    plugin interfacing parts of QtGui, for example the QWindow, QScreen and
    QWindowSystemInterface implementation.

    There are now up to three active coordinate systems in Qt:

     ---------------------------------------------------
    |  Application            Device Independent Pixels |   devicePixelRatio
    |  Qt Widgets                                       |         =
    |  Qt Gui                                           |
    |---------------------------------------------------|   Qt Scale Factor
    |  Qt Gui QPlatform*      Native Pixels             |         *
    |  Qt platform plugin                               |
    |---------------------------------------------------|   OS Scale Factor
    |  Display                Device Pixels             |
    |  (Graphics Buffers)                               |
    -----------------------------------------------------

    This is an simplification and shows the main coordinate system. All layers
    may work with device pixels in specific cases: OpenGL, creating the backing
    store, and QPixmap management. The "Native Pixels" coordinate system is
    internal to Qt and should not be exposed to Qt users: Seen from the outside
    there are only two coordinate systems: device independent pixels and device
    pixels.

    The devicePixelRatio seen by applications is the product of the Qt scale
    factor and the OS scale factor (see QWindow::devicePixelRatio()). The value
    of the scale factors may be 1, in which case two or more of the coordinate
    systems are equivalent. Platforms that (may) have an OS scale factor include
    macOS, iOS, Wayland, and Web(Assembly).

    Note that the API implemented in this file do use the OS scale factor, and
    is used for converting between device independent and native pixels only.

    Configuration Examples:

    'Classic': Device Independent Pixels = Native Pixels = Device Pixels
     ---------------------------------------------------    devicePixelRatio: 1
    |  Application / Qt Gui             100 x 100       |
    |                                                   |   Qt Scale Factor: 1
    |  Qt Platform / OS                 100 x 100       |
    |                                                   |   OS Scale Factor: 1
    |  Display                          100 x 100       |
    -----------------------------------------------------

    '2x Apple Device': Device Independent Pixels = Native Pixels
     ---------------------------------------------------    devicePixelRatio: 2
    |  Application / Qt Gui             100 x 100       |
    |                                                   |   Qt Scale Factor: 1
    |  Qt Platform / OS                 100 x 100       |
    |---------------------------------------------------|   OS Scale Factor: 2
    |  Display                          200 x 200       |
    -----------------------------------------------------

    'Windows at 200%': Native Pixels = Device Pixels
     ---------------------------------------------------    devicePixelRatio: 2
    |  Application / Qt Gui             100 x 100       |
    |---------------------------------------------------|   Qt Scale Factor: 2
    |  Qt Platform / OS                 200 x 200       |
    |                                                   |   OS Scale Factor: 1
    |  Display                          200 x 200       |
    -----------------------------------------------------

    * Configuration

    - Enabling: In Qt 6, high-dpi scaling (the functionality implemented in this file)
      is always enabled. The Qt scale factor value is typically determined by the
      QPlatformScreen implementation - see below.

      There is one environment variable based opt-out option: set QT_ENABLE_HIGH_DPI_SCALING=0.
      Keep in mind that this does not affect the OS scale factor, which is controlled by
      the operating system.

    - Qt scale factor value: The Qt scale factor is the product of the screen scale
      factor and the global scale factor, which are independently either set or determined
      by the platform plugin. Several APIs are offered for this, targeting both developers
      and end users. All scale factors are of type qreal.

      1) Per-screen scale factors

        Per-screen scale factors are computed based on logical DPI provided by
        by the platform plugin.

        The platform plugin implements DPI accessor functions:
            QDpi QPlatformScreen::logicalDpi()
            QDpi QPlatformScreen::logicalBaseDpi()

        QHighDpiScaling then computes the per-screen scale factor as follows:

            factor = logicalDpi / logicalBaseDpi

        Alternatively, QT_SCREEN_SCALE_FACTORS can be used to set the screen
        scale factors.

      2) The global scale factor

        The QT_SCALE_FACTOR environment variable can be used to set a global scale
        factor which applies to all application windows. This allows developing and
        testing at any DPR, independently of available hardware and without changing
        global desktop settings.

    - Rounding

      Qt 6 does not round scale factors by default. Qt 5 rounds the screen scale factor
      to the nearest integer (except for Qt on Android which does not round).

      The rounding policy can be set by the application, or on the environment:

        Application (C++):    QGuiApplication::setHighDpiScaleFactorRoundingPolicy()
        User (environment):   QT_SCALE_FACTOR_ROUNDING_POLICY

      Note that the OS scale factor, and global scale factors set with QT_SCALE_FACTOR
      are never rounded by Qt.

    * C++ API Overview

    - Coordinate Conversion ("scaling")

      The QHighDpi namespace provides several functions for converting geometry
      between the device independent and native coordinate systems. These should
      be used when calling "QPlatform*" API from QtGui. Callers are responsible
      for selecting a function variant based on geometry type:

            Type                        From Native                              To Native
        local               :    QHighDpi::fromNativeLocalPosition()    QHighDpi::toNativeLocalPosition()
        global (screen)     :    QHighDpi::fromNativeGlobalPosition()   QHighDpi::toNativeGlobalPosition()
        QWindow::geometry() :    QHighDpi::fromNativeWindowGeometry()   QHighDpi::toNativeWindowGeometry()
        sizes, margins, etc :    QHighDpi::fromNativePixels()           QHighDpi::toNativePixels()

     The conversion functions take two arguments; the geometry and a context:

        QSize nativeSize = toNativePixels(deviceIndependentSize, window);

     The context is usually a QWindow instance, but can also be a QScreen instance,
     or the corresponding QPlatform classes.

    - Activation

      QHighDpiScaling::isActive() returns true iff
            Qt high-dpi scaling is enabled (e.g. with AA_EnableHighDpiScaling) AND
            there is a Qt scale factor != 1

      (the value of the OS scale factor does not affect this API)

    - Calling QtGui from the platform plugins

      Platform plugin code should be careful about calling QtGui geometry accessor
      functions like geometry():

         QRect r = window->geometry();

      In this case the returned geometry is in the wrong coordinate system (device independent
      instead of native pixels). Fix this by adding a conversion call:

         QRect r = QHighDpi::toNativeWindowGeometry(window->geometry());

      (Also consider if the call to QtGui is really needed - prefer calling QPlatform* API.)
*/

qreal QHighDpiScaling::m_factor = 1.0;
bool QHighDpiScaling::m_active = false; //"overall active" - is there any scale factor set.
bool QHighDpiScaling::m_usePlatformPluginDpi = false; // use scale factor based on platform plugin DPI
bool QHighDpiScaling::m_platformPluginDpiScalingActive  = false; // platform plugin DPI gives a scale factor > 1
bool QHighDpiScaling::m_globalScalingActive = false; // global scale factor is active
bool QHighDpiScaling::m_screenFactorSet = false; // QHighDpiScaling::setScreenFactor has been used

/*
    Initializes the QHighDpiScaling global variables. Called before the
    platform plugin is created.
*/

static inline bool usePlatformPluginDpi()
{
    // Determine if we should set a scale factor based on the logical DPI
    // reported by the platform plugin.

    bool enableEnvValueOk;
    const int enableEnvValue = qEnvironmentVariableIntValue(enableHighDpiScalingEnvVar, &enableEnvValueOk);
    if (enableEnvValueOk && enableEnvValue < 1)
        return false;

    // Enable by default
    return true;
}

qreal QHighDpiScaling::rawScaleFactor(const QPlatformScreen *screen)
{
    // Determine if physical DPI should be used
    static const bool usePhysicalDpi = qEnvironmentVariableAsBool(usePhysicalDpiEnvVar, false);

    // Calculate scale factor beased on platform screen DPI values
    qreal factor;
    QDpi platformBaseDpi = screen->logicalBaseDpi();
    if (usePhysicalDpi) {
        QSize sz = screen->geometry().size();
        QSizeF psz = screen->physicalSize();
        qreal platformPhysicalDpi = ((sz.height() / psz.height()) + (sz.width() / psz.width())) * qreal(25.4 * 0.5);
        factor = qreal(platformPhysicalDpi) / qreal(platformBaseDpi.first);
    } else {
        const QDpi platformLogicalDpi = QPlatformScreen::overrideDpi(screen->logicalDpi());
        factor = qreal(platformLogicalDpi.first) / qreal(platformBaseDpi.first);
    }

    return factor;
}

template <class EnumType>
struct EnumLookup
{
    const char *name;
    EnumType value;
};

template <class EnumType>
static bool operator==(const EnumLookup<EnumType> &e1, const EnumLookup<EnumType> &e2)
{
    return qstricmp(e1.name, e2.name) == 0;
}

template <class EnumType>
static QByteArray joinEnumValues(const EnumLookup<EnumType> *i1, const EnumLookup<EnumType> *i2)
{
    QByteArray result;
    for (; i1 < i2; ++i1) {
        if (!result.isEmpty())
            result += QByteArrayLiteral(", ");
        result += i1->name;
    }
    return result;
}

using ScaleFactorRoundingPolicyLookup = EnumLookup<Qt::HighDpiScaleFactorRoundingPolicy>;

static const ScaleFactorRoundingPolicyLookup scaleFactorRoundingPolicyLookup[] =
{
    {"Round", Qt::HighDpiScaleFactorRoundingPolicy::Round},
    {"Ceil", Qt::HighDpiScaleFactorRoundingPolicy::Ceil},
    {"Floor", Qt::HighDpiScaleFactorRoundingPolicy::Floor},
    {"RoundPreferFloor", Qt::HighDpiScaleFactorRoundingPolicy::RoundPreferFloor},
    {"PassThrough", Qt::HighDpiScaleFactorRoundingPolicy::PassThrough}
};

static Qt::HighDpiScaleFactorRoundingPolicy
    lookupScaleFactorRoundingPolicy(const QByteArray &v)
{
    auto end = std::end(scaleFactorRoundingPolicyLookup);
    auto it = std::find(std::begin(scaleFactorRoundingPolicyLookup), end,
                        ScaleFactorRoundingPolicyLookup{v.constData(), Qt::HighDpiScaleFactorRoundingPolicy::Unset});
    return it != end ? it->value : Qt::HighDpiScaleFactorRoundingPolicy::Unset;
}

using DpiAdjustmentPolicyLookup = EnumLookup<QHighDpiScaling::DpiAdjustmentPolicy>;

static const DpiAdjustmentPolicyLookup dpiAdjustmentPolicyLookup[] =
{
    {"AdjustDpi", QHighDpiScaling::DpiAdjustmentPolicy::Enabled},
    {"DontAdjustDpi", QHighDpiScaling::DpiAdjustmentPolicy::Disabled},
    {"AdjustUpOnly", QHighDpiScaling::DpiAdjustmentPolicy::UpOnly}
};

static QHighDpiScaling::DpiAdjustmentPolicy
    lookupDpiAdjustmentPolicy(const QByteArray &v)
{
    auto end = std::end(dpiAdjustmentPolicyLookup);
    auto it = std::find(std::begin(dpiAdjustmentPolicyLookup), end,
                        DpiAdjustmentPolicyLookup{v.constData(), QHighDpiScaling::DpiAdjustmentPolicy::Unset});
    return it != end ? it->value : QHighDpiScaling::DpiAdjustmentPolicy::Unset;
}

qreal QHighDpiScaling::roundScaleFactor(qreal rawFactor)
{
    // Apply scale factor rounding policy. Using mathematically correct rounding
    // may not give the most desirable visual results, especially for
    // critical fractions like .5. In general, rounding down results in visual
    // sizes that are smaller than the ideal size, and opposite for rounding up.
    // Rounding down is then preferable since "small UI" is a more acceptable
    // high-DPI experience than "large UI".
    static auto scaleFactorRoundingPolicy = Qt::HighDpiScaleFactorRoundingPolicy::Unset;

    // Determine rounding policy
    if (scaleFactorRoundingPolicy == Qt::HighDpiScaleFactorRoundingPolicy::Unset) {
        // Check environment
        if (qEnvironmentVariableIsSet(scaleFactorRoundingPolicyEnvVar)) {
            QByteArray policyText = qgetenv(scaleFactorRoundingPolicyEnvVar);
            auto policyEnumValue = lookupScaleFactorRoundingPolicy(policyText);
            if (policyEnumValue != Qt::HighDpiScaleFactorRoundingPolicy::Unset) {
                scaleFactorRoundingPolicy = policyEnumValue;
            } else {
                auto values = joinEnumValues(std::begin(scaleFactorRoundingPolicyLookup),
                                             std::end(scaleFactorRoundingPolicyLookup));
                qWarning("Unknown scale factor rounding policy: %s. Supported values are: %s.",
                         policyText.constData(), values.constData());
            }
        }

        // Check application object if no environment value was set.
        if (scaleFactorRoundingPolicy == Qt::HighDpiScaleFactorRoundingPolicy::Unset) {
            scaleFactorRoundingPolicy = QGuiApplication::highDpiScaleFactorRoundingPolicy();
        } else {
            // Make application setting reflect environment
            QGuiApplication::setHighDpiScaleFactorRoundingPolicy(scaleFactorRoundingPolicy);
        }
    }

    // Apply rounding policy.
    qreal roundedFactor = rawFactor;
    switch (scaleFactorRoundingPolicy) {
    case Qt::HighDpiScaleFactorRoundingPolicy::Round:
        roundedFactor = qRound(rawFactor);
        break;
    case Qt::HighDpiScaleFactorRoundingPolicy::Ceil:
        roundedFactor = qCeil(rawFactor);
        break;
    case Qt::HighDpiScaleFactorRoundingPolicy::Floor:
        roundedFactor = qFloor(rawFactor);
        break;
    case Qt::HighDpiScaleFactorRoundingPolicy::RoundPreferFloor:
        // Round up for .75 and higher. This favors "small UI" over "large UI".
        roundedFactor = rawFactor - qFloor(rawFactor) < 0.75
            ? qFloor(rawFactor) : qCeil(rawFactor);
        break;
    case Qt::HighDpiScaleFactorRoundingPolicy::PassThrough:
    case Qt::HighDpiScaleFactorRoundingPolicy::Unset:
        break;
    }

    // Clamp the minimum factor to 1. Qt does not currently render
    // correctly with factors less than 1.
    roundedFactor = qMax(roundedFactor, qreal(1));

    return roundedFactor;
}

QDpi QHighDpiScaling::effectiveLogicalDpi(const QPlatformScreen *screen, qreal rawFactor, qreal roundedFactor)
{
    // Apply DPI adjustment policy, if needed. If enabled this will change the
    // reported logical DPI to account for the difference between the rounded
    // scale factor and the actual scale factor. The effect is that text size
    // will be correct for the screen dpi, but may be (slightly) out of sync
    // with the rest of the UI. The amount of out-of-synch-ness depends on how
    // well user code handles a non-standard DPI values, but since the
    // adjustment is small (typically +/- 48 max) this might be OK.
    static auto dpiAdjustmentPolicy = DpiAdjustmentPolicy::Unset;

    // Determine adjustment policy.
    if (dpiAdjustmentPolicy == DpiAdjustmentPolicy::Unset) {
        if (qEnvironmentVariableIsSet(dpiAdjustmentPolicyEnvVar)) {
            QByteArray policyText = qgetenv(dpiAdjustmentPolicyEnvVar);
            auto policyEnumValue = lookupDpiAdjustmentPolicy(policyText);
            if (policyEnumValue != DpiAdjustmentPolicy::Unset) {
                dpiAdjustmentPolicy = policyEnumValue;
            } else {
                auto values = joinEnumValues(std::begin(dpiAdjustmentPolicyLookup),
                                             std::end(dpiAdjustmentPolicyLookup));
                qWarning("Unknown DPI adjustment policy: %s. Supported values are: %s.",
                         policyText.constData(), values.constData());
            }
        }
        if (dpiAdjustmentPolicy == DpiAdjustmentPolicy::Unset)
            dpiAdjustmentPolicy = DpiAdjustmentPolicy::UpOnly;
    }

    // Apply adjustment policy.
    const QDpi baseDpi = screen->logicalBaseDpi();
    const qreal dpiAdjustmentFactor = rawFactor / roundedFactor;

    // Return the base DPI for cases where there is no adjustment
    if (dpiAdjustmentPolicy == DpiAdjustmentPolicy::Disabled)
        return baseDpi;
    if (dpiAdjustmentPolicy == DpiAdjustmentPolicy::UpOnly && dpiAdjustmentFactor < 1)
        return baseDpi;

    return QDpi(baseDpi.first * dpiAdjustmentFactor, baseDpi.second * dpiAdjustmentFactor);
}

void QHighDpiScaling::initHighDpiScaling()
{
    // Determine if there is a global scale factor set.
    m_factor = initialGlobalScaleFactor();
    m_globalScalingActive = !qFuzzyCompare(m_factor, qreal(1));

    m_usePlatformPluginDpi = usePlatformPluginDpi();

    m_platformPluginDpiScalingActive  = false; //set in updateHighDpiScaling below

    m_active = m_globalScalingActive || m_usePlatformPluginDpi;
}

void QHighDpiScaling::updateHighDpiScaling()
{
    m_usePlatformPluginDpi = usePlatformPluginDpi();

    if (m_usePlatformPluginDpi && !m_platformPluginDpiScalingActive ) {
        const auto screens = QGuiApplication::screens();
        for (QScreen *screen : screens) {
            if (!qFuzzyCompare(screenSubfactor(screen->handle()), qreal(1))) {
                m_platformPluginDpiScalingActive  = true;
                break;
            }
        }
    }
    if (qEnvironmentVariableIsSet(screenFactorsEnvVar)) {
        int i = 0;
        const QString spec = qEnvironmentVariable(screenFactorsEnvVar);
        const auto specs = QStringView{spec}.split(u';');
        for (const auto &spec : specs) {
            int equalsPos = spec.lastIndexOf(QLatin1Char('='));
            qreal factor = 0;
            if (equalsPos > 0) {
                // support "name=factor"
                bool ok;
                const auto name = spec.left(equalsPos);
                factor = spec.mid(equalsPos + 1).toDouble(&ok);
                if (ok && factor > 0 ) {
                    const auto screens = QGuiApplication::screens();
                    for (QScreen *s : screens) {
                        if (s->name() == name) {
                            setScreenFactor(s, factor);
                            break;
                        }
                    }
                }
            } else {
                // listing screens in order
                bool ok;
                factor = spec.toDouble(&ok);
                if (ok && factor > 0 && i < QGuiApplication::screens().count()) {
                    QScreen *screen = QGuiApplication::screens().at(i);
                    setScreenFactor(screen, factor);
                }
            }
            ++i;
        }
    }
    m_active = m_globalScalingActive || m_screenFactorSet || m_platformPluginDpiScalingActive ;
}

/*
    Sets the global scale factor which is applied to all windows.
*/
void QHighDpiScaling::setGlobalFactor(qreal factor)
{
    if (qFuzzyCompare(factor, m_factor))
        return;
    if (!QGuiApplication::allWindows().isEmpty())
        qWarning("QHighDpiScaling::setFactor: Should only be called when no windows exist.");

    m_globalScalingActive = !qFuzzyCompare(factor, qreal(1));
    m_factor = m_globalScalingActive ? factor : qreal(1);
    m_active = m_globalScalingActive || m_screenFactorSet || m_platformPluginDpiScalingActive ;
    const auto screens = QGuiApplication::screens();
    for (QScreen *screen : screens)
         screen->d_func()->updateHighDpi();
}

static const char scaleFactorProperty[] = "_q_scaleFactor";

/*
    Sets a per-screen scale factor.
*/
void QHighDpiScaling::setScreenFactor(QScreen *screen, qreal factor)
{
    if (!qFuzzyCompare(factor, qreal(1))) {
        m_screenFactorSet = true;
        m_active = true;
    }

    // Prefer associating the factor with screen name over the object
    // since the screen object may be deleted on screen disconnects.
    const QString name = screen->name();
    if (name.isEmpty())
        screen->setProperty(scaleFactorProperty, QVariant(factor));
    else
        qNamedScreenScaleFactors()->insert(name, factor);

    // hack to force re-evaluation of screen geometry
    if (screen->handle())
        screen->d_func()->setPlatformScreen(screen->handle()); // updates geometries based on scale factor
}

QPoint QHighDpiScaling::mapPositionToNative(const QPoint &pos, const QPlatformScreen *platformScreen)
{
    if (!platformScreen)
        return pos;
    const qreal scaleFactor = factor(platformScreen);
    const QPoint topLeft = platformScreen->geometry().topLeft();
    return (pos - topLeft) * scaleFactor + topLeft;
}

QPoint QHighDpiScaling::mapPositionFromNative(const QPoint &pos, const QPlatformScreen *platformScreen)
{
    if (!platformScreen)
        return pos;
    const qreal scaleFactor = factor(platformScreen);
    const QPoint topLeft = platformScreen->geometry().topLeft();
    return (pos - topLeft) / scaleFactor + topLeft;
}

qreal QHighDpiScaling::screenSubfactor(const QPlatformScreen *screen)
{
    auto factor = qreal(1.0);
    if (!screen)
        return factor;

    // Unlike the other code where factors are combined by multiplication,
    // factors from QT_SCREEN_SCALE_FACTORS takes precedence over the factor
    // computed from platform plugin DPI. The rationale is that the user is
    // setting the factor to override erroneous DPI values.
    bool screenPropertyUsed = false;
    if (m_screenFactorSet) {
        // Check if there is a factor set on the screen object or associated
        // with the screen name. These are mutually exclusive, so checking
        // order is not significant.
        if (auto qScreen = screen->screen()) {
            auto screenFactor = qScreen->property(scaleFactorProperty).toReal(&screenPropertyUsed);
            if (screenPropertyUsed)
                factor = screenFactor;
        }

        if (!screenPropertyUsed) {
            auto byNameIt = qNamedScreenScaleFactors()->constFind(screen->name());
            if ((screenPropertyUsed = byNameIt != qNamedScreenScaleFactors()->cend()))
                factor = *byNameIt;
        }
    }

    if (!screenPropertyUsed && m_usePlatformPluginDpi)
        factor = roundScaleFactor(rawScaleFactor(screen));

    return factor;
}

QDpi QHighDpiScaling::logicalDpi(const QScreen *screen)
{
    // (Note: m_active test is performed at call site.)
    if (!screen || !screen->handle())
        return QDpi(96, 96);

    if (!m_usePlatformPluginDpi) {
        const qreal screenScaleFactor = screenSubfactor(screen->handle());
        const QDpi dpi = QPlatformScreen::overrideDpi(screen->handle()->logicalDpi());
        return QDpi{ dpi.first / screenScaleFactor, dpi.second / screenScaleFactor };
    }

    const qreal scaleFactor = rawScaleFactor(screen->handle());
    const qreal roundedScaleFactor = roundScaleFactor(scaleFactor);
    return effectiveLogicalDpi(screen->handle(), scaleFactor, roundedScaleFactor);
}

// Returns the screen containing \a position, using \a guess as a starting point
// for the search. \a guess might be nullptr. Returns nullptr if \a position is outside
// of all screens.
QScreen *QHighDpiScaling::screenForPosition(QHighDpiScaling::Point position, QScreen *guess)
{
    if (position.kind == QHighDpiScaling::Point::Invalid)
        return nullptr;

    auto getPlatformScreenGuess = [](QScreen *maybeScreen) -> QPlatformScreen * {
        if (maybeScreen)
            return maybeScreen->handle();
        if (QScreen *primary = QGuiApplication::primaryScreen())
            return primary->handle();
        return nullptr;
    };

    QPlatformScreen *platformGuess = getPlatformScreenGuess(guess);
    if (!platformGuess)
        return nullptr;

    auto onScreen = [](QHighDpiScaling::Point position, const QPlatformScreen *platformScreen) -> bool {
        return position.kind == Point::Native
          ?  platformScreen->geometry().contains(position.point)
          :  platformScreen->screen()->geometry().contains(position.point);
    };

    // is the guessed screen correct?
    if (onScreen(position, platformGuess))
        return platformGuess->screen();

    // search sibling screens
    const auto screens = platformGuess->virtualSiblings();
    for (const QPlatformScreen *screen : screens) {
        if (onScreen(position, screen))
            return screen->screen();
    }

    return nullptr;
}

QHighDpiScaling::ScaleAndOrigin QHighDpiScaling::scaleAndOrigin(const QPlatformScreen *platformScreen, QHighDpiScaling::Point position)
{
    Q_UNUSED(position)
    if (!m_active)
        return { qreal(1), QPoint() };
    if (!platformScreen)
        return { m_factor, QPoint() }; // the global factor
    return { m_factor * screenSubfactor(platformScreen), platformScreen->geometry().topLeft() };
}

QHighDpiScaling::ScaleAndOrigin QHighDpiScaling::scaleAndOrigin(const QScreen *screen, QHighDpiScaling::Point position)
{
    Q_UNUSED(position)
    if (!m_active)
        return { qreal(1), QPoint() };
    if (!screen)
        return { m_factor, QPoint() }; // the global factor
    return scaleAndOrigin(screen->handle(), position);
}

QHighDpiScaling::ScaleAndOrigin QHighDpiScaling::scaleAndOrigin(const QWindow *window, QHighDpiScaling::Point position)
{
    if (!m_active)
        return { qreal(1), QPoint() };

    // Determine correct screen; use the screen which contains the given
    // position if a valid position is passed.
    QScreen *screen = window ? window->screen() : QGuiApplication::primaryScreen();
    QScreen *overrideScreen = QHighDpiScaling::screenForPosition(position, screen);
    QScreen *targetScreen = overrideScreen ? overrideScreen : screen;
    return scaleAndOrigin(targetScreen, position);
}

#else
QHighDpiScaling::ScaleAndOrigin QHighDpiScaling::scaleAndOrigin(const QPlatformScreen *, QPoint *)
{
    return { qreal(1), QPoint() };
}

QHighDpiScaling::ScaleAndOrigin QHighDpiScaling::scaleAndOrigin(const QScreen *, QPoint *)
{
    return { qreal(1), QPoint() };
}

QHighDpiScaling::ScaleAndOrigin QHighDpiScaling::scaleAndOrigin(const QWindow *, QPoint *)
{
    return { qreal(1), QPoint() };
}
#endif //QT_NO_HIGHDPISCALING
QT_END_NAMESPACE
