/****************************************************************************
**
** Copyright (C) 2021 The Qt Company Ltd.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the QtCore module of the Qt Toolkit.
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

#ifndef QNATIVEINTERFACE_H
#define QNATIVEINTERFACE_H

#include <QtCore/qglobal.h>
#include <QtCore/qloggingcategory.h>

QT_BEGIN_NAMESPACE

// We declare a virtual non-inline function in the form
// of the destructor, making it the key function. This
// ensures that the typeinfo of the class is exported.
// By being protected, we also ensure that pointers to
// the interface can't be deleted.
#define QT_DECLARE_NATIVE_INTERFACE_3(NativeInterface, Revision, BaseType) \
    protected: \
        virtual ~NativeInterface(); \
        \
        struct TypeInfo { \
            using baseType = BaseType; \
            static constexpr char const *name = QT_STRINGIFY(NativeInterface); \
            static constexpr int revision = Revision; \
        }; \
        \
        template <typename, typename> \
        friend struct QNativeInterface::Private::has_type_info; \
        \
        template <typename> \
        friend bool constexpr QNativeInterface::Private::hasTypeInfo(); \
        \
        template <typename> \
        friend struct QNativeInterface::Private::TypeInfo; \
    public: \
        NativeInterface() = default; \
        Q_DISABLE_COPY_MOVE(NativeInterface)

// Revisioned interfaces only make sense when exposed through a base
// type via QT_DECLARE_NATIVE_INTERFACE_ACCESSOR, as the revision
// checks happen at that level (and not for normal dynamic_casts).
#define QT_DECLARE_NATIVE_INTERFACE_2(NativeInterface, Revision) \
    static_assert(false, "Must provide a base type when specifying revision");

#define QT_DECLARE_NATIVE_INTERFACE_1(NativeInterface) \
    QT_DECLARE_NATIVE_INTERFACE_3(NativeInterface, 0, void)

#define QT_DECLARE_NATIVE_INTERFACE(...) \
    QT_OVERLOADED_MACRO(QT_DECLARE_NATIVE_INTERFACE, __VA_ARGS__)

namespace QNativeInterface::Private {

    // Basic type-trait to verify that a given native interface has
    // all the required type information for us to evaluate it.
    template <typename NativeInterface, typename = void>
    struct has_type_info : std::false_type {};

    // The type-trait is friended by TypeInfo, so that we can
    // evaluate TypeInfo in the template arguments.
    template <typename NativeInterface>
    struct has_type_info<NativeInterface, std::void_t<
        typename NativeInterface::TypeInfo,
        typename NativeInterface::TypeInfo::baseType,
        decltype(&NativeInterface::TypeInfo::name),
        decltype(&NativeInterface::TypeInfo::revision)
        >> : std::true_type {};

    // We need to wrap the instantiation of has_type_info in a
    // function friended by TypeInfo, otherwise MSVC will not
    // let us evaluate TypeInfo in the template arguments.
    template <typename NativeInterface>
    bool constexpr hasTypeInfo()
    {
        return has_type_info<NativeInterface>::value;
    }

    template <typename NativeInterface>
    struct TypeInfo
    {
        // To ensure SFINAE works for hasTypeInfo we can't use it in a constexpr
        // variable that also includes an expression that relies on the type
        // info. This helper variable is okey, as it it self contained.
        static constexpr bool haveTypeInfo = hasTypeInfo<NativeInterface>();

        // We can then use the helper variable in a constexpr condition in a
        // function, which does not break SFINAE if haveTypeInfo is false.
        template <typename BaseType>
        static constexpr bool isCompatibleHelper()
        {
            if constexpr (haveTypeInfo)
                return std::is_base_of<typename NativeInterface::TypeInfo::baseType, BaseType>::value;
            else
                return false;
        }

        // MSVC however doesn't like constexpr functions in enable_if_t conditions,
        // so we need to wrap it yet again in a constexpr variable. This is fine,
        // as all the SFINAE magic has been resolved at this point.
        template <typename BaseType>
        static constexpr bool isCompatibleWith = isCompatibleHelper<BaseType>();

        // The revision and name accessors are not used in enable_if_t conditions,
        // so we can leave them as constexpr functions. As this class template is
        // friended by TypeInfo we can access the protected members of TypeInfo.
        static constexpr int revision()
        {
            if constexpr (haveTypeInfo)
                return NativeInterface::TypeInfo::revision;
            else
                return 0;
        }

        static constexpr char const *name()
        {
            if constexpr (haveTypeInfo)
                return NativeInterface::TypeInfo::name;
            else
                return nullptr;
        }
    };

    // Wrapper type to make the error message in case
    // of incompatible interface types read better.
    template <typename I>
    struct NativeInterface : TypeInfo<I> {};

    Q_CORE_EXPORT Q_DECLARE_LOGGING_CATEGORY(lcNativeInterface)

} // QNativeInterface::Private

// Declares an accessor for the native interface
#define QT_DECLARE_NATIVE_INTERFACE_ACCESSOR(T) \
    template <typename NativeInterface, typename TypeInfo = QNativeInterface::Private::NativeInterface<NativeInterface>, \
    typename BaseType = T, std::enable_if_t<TypeInfo::template isCompatibleWith<T>, bool> = true> \
    NativeInterface *nativeInterface() const \
    { \
        return static_cast<NativeInterface*>(resolveInterface( \
            TypeInfo::name(), TypeInfo::revision())); \
    } \
    protected: \
        void *resolveInterface(const char *name, int revision) const; \
    public:

// Provides a definition for the interface destructor
#define QT_DEFINE_NATIVE_INTERFACE_2(Namespace, InterfaceClass) \
    QT_PREPEND_NAMESPACE(Namespace)::InterfaceClass::~InterfaceClass() = default

#define QT_DEFINE_NATIVE_INTERFACE(...) QT_OVERLOADED_MACRO(QT_DEFINE_NATIVE_INTERFACE, QNativeInterface, __VA_ARGS__)
#define QT_DEFINE_PRIVATE_NATIVE_INTERFACE(...) QT_OVERLOADED_MACRO(QT_DEFINE_NATIVE_INTERFACE, QNativeInterface::Private, __VA_ARGS__)

#define QT_NATIVE_INTERFACE_RETURN_IF(NativeInterface, baseType) \
    { \
        using QNativeInterface::Private::lcNativeInterface; \
        using QNativeInterface::Private::TypeInfo; \
        qCDebug(lcNativeInterface, "Comparing requested interface name %s with available %s", \
                name, TypeInfo<NativeInterface>::name()); \
        if (qstrcmp(name, TypeInfo<NativeInterface>::name()) == 0) { \
            qCDebug(lcNativeInterface, "Match for interface %s. Comparing revisions (requested %d / available %d)", \
                name, revision, TypeInfo<NativeInterface>::revision()); \
            if (revision == TypeInfo<NativeInterface>::revision()) { \
                qCDebug(lcNativeInterface) << "Full match. Returning dynamic cast of" << baseType; \
                return dynamic_cast<NativeInterface*>(baseType); \
            } else { \
                qCWarning(lcNativeInterface, "Native interface revision mismatch (requested %d / available %d) for interface %s", \
                    revision, TypeInfo<NativeInterface>::revision(), name); \
                return nullptr; \
            } \
        } else { \
            qCDebug(lcNativeInterface, "No match for requested interface name %s", name); \
        } \
    }

QT_END_NAMESPACE

#endif // QNATIVEINTERFACE_H
