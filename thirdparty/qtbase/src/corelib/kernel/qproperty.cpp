/****************************************************************************
**
** Copyright (C) 2020 The Qt Company Ltd.
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

#include "qproperty.h"
#include "qproperty_p.h"

#include <qscopedvaluerollback.h>
#include <QScopeGuard>

QT_BEGIN_NAMESPACE

using namespace QtPrivate;

void QPropertyBindingPrivatePtr::destroyAndFreeMemory()
{
    QPropertyBindingPrivate::destroyAndFreeMemory(static_cast<QPropertyBindingPrivate *>(d));
}

void QPropertyBindingPrivatePtr::reset(QtPrivate::RefCounted *ptr) noexcept
{
    if (ptr != d) {
        if (ptr)
            ptr->ref++;
        auto *old = qExchange(d, ptr);
        if (old && (--old->ref == 0))
            QPropertyBindingPrivate::destroyAndFreeMemory(static_cast<QPropertyBindingPrivate *>(d));
    }
}


void QPropertyBindingDataPointer::addObserver(QPropertyObserver *observer)
{
    if (auto *binding = bindingPtr()) {
        observer->prev = &binding->firstObserver.ptr;
        observer->next = binding->firstObserver.ptr;
        if (observer->next)
            observer->next->prev = &observer->next;
        binding->firstObserver.ptr = observer;
    } else {
        Q_ASSERT(!(ptr->d_ptr & QPropertyBindingData::BindingBit));
        auto firstObserver = reinterpret_cast<QPropertyObserver*>(ptr->d_ptr);
        observer->prev = reinterpret_cast<QPropertyObserver**>(&ptr->d_ptr);
        observer->next = firstObserver;
        if (observer->next)
            observer->next->prev = &observer->next;
    }
    setFirstObserver(observer);
}

QPropertyBindingPrivate::~QPropertyBindingPrivate()
{
    if (firstObserver)
        firstObserver.unlink();
    if (vtable->size)
        vtable->destroy(reinterpret_cast<std::byte *>(this)
                        + QPropertyBindingPrivate::getSizeEnsuringAlignment());
}

void QPropertyBindingPrivate::unlinkAndDeref()
{
    propertyDataPtr = nullptr;
    if (--ref == 0)
        destroyAndFreeMemory(this);
}

void QPropertyBindingPrivate::markDirtyAndNotifyObservers()
{
    if (eagerlyUpdating) {
        error = QPropertyBindingError(QPropertyBindingError::BindingLoop);
        if (isQQmlPropertyBinding)
            errorCallBack(this);
        return;
    }
    if (dirty)
        return;
    dirty = true;

    eagerlyUpdating = true;
    QScopeGuard guard([&](){eagerlyUpdating = false;});
    bool knownToHaveChanged = false;
    if (requiresEagerEvaluation()) {
        // these are compat properties that we will need to evaluate eagerly
        if (!evaluateIfDirtyAndReturnTrueIfValueChanged(propertyDataPtr))
            return;
        knownToHaveChanged = true;
    }
    if (firstObserver)
        firstObserver.notify(this, propertyDataPtr, knownToHaveChanged);
    if (hasStaticObserver)
        staticObserverCallback(propertyDataPtr);
}

bool QPropertyBindingPrivate::evaluateIfDirtyAndReturnTrueIfValueChanged_helper(const QUntypedPropertyData *data, QBindingStatus *status)
{
    Q_ASSERT(dirty);

    if (updating) {
        error = QPropertyBindingError(QPropertyBindingError::BindingLoop);
        if (isQQmlPropertyBinding)
            errorCallBack(this);
        return false;
    }

    /*
     * Evaluating the binding might lead to the binding being broken. This can
     * cause ref to reach zero at the end of the function.  However, the
     * updateGuard's destructor will then still trigger, trying to set the
     * updating bool to its old value
     * To prevent this, we create a QPropertyBindingPrivatePtr which ensures
     * that the object is still alive when updateGuard's dtor runs.
     */
    QPropertyBindingPrivatePtr keepAlive {this};
    QScopedValueRollback<bool> updateGuard(updating, true);

    BindingEvaluationState evaluationFrame(this, status);

    bool changed = false;

    Q_ASSERT(propertyDataPtr == data);
    QUntypedPropertyData *mutable_data = const_cast<QUntypedPropertyData *>(data);

    if (hasBindingWrapper) {
        changed = staticBindingWrapper(metaType, mutable_data, {vtable, reinterpret_cast<std::byte *>(this)+QPropertyBindingPrivate::getSizeEnsuringAlignment()});
    } else {
        changed = vtable->call(metaType, mutable_data, reinterpret_cast<std::byte *>(this)+ QPropertyBindingPrivate::getSizeEnsuringAlignment());
    }

    dirty = false;
    return changed;
}

QUntypedPropertyBinding::QUntypedPropertyBinding() = default;

QUntypedPropertyBinding::QUntypedPropertyBinding(QMetaType metaType, const BindingFunctionVTable *vtable, void *function,
                                                 const QPropertyBindingSourceLocation &location)
{
    std::byte *mem = new std::byte[QPropertyBindingPrivate::getSizeEnsuringAlignment() + vtable->size]();
    d = new(mem) QPropertyBindingPrivate(metaType, vtable, std::move(location));
    vtable->moveConstruct(mem + QPropertyBindingPrivate::getSizeEnsuringAlignment(), function);
}

QUntypedPropertyBinding::QUntypedPropertyBinding(QUntypedPropertyBinding &&other)
    : d(std::move(other.d))
{
}

QUntypedPropertyBinding::QUntypedPropertyBinding(const QUntypedPropertyBinding &other)
    : d(other.d)
{
}

QUntypedPropertyBinding &QUntypedPropertyBinding::operator=(const QUntypedPropertyBinding &other)
{
    d = other.d;
    return *this;
}

QUntypedPropertyBinding &QUntypedPropertyBinding::operator=(QUntypedPropertyBinding &&other)
{
    d = std::move(other.d);
    return *this;
}

QUntypedPropertyBinding::QUntypedPropertyBinding(QPropertyBindingPrivate *priv)
    : d(priv)
{
}

QUntypedPropertyBinding::~QUntypedPropertyBinding()
{
}

bool QUntypedPropertyBinding::isNull() const
{
    return !d;
}

QPropertyBindingError QUntypedPropertyBinding::error() const
{
    if (!d)
        return QPropertyBindingError();
    return static_cast<QPropertyBindingPrivate *>(d.get())->bindingError();
}

QMetaType QUntypedPropertyBinding::valueMetaType() const
{
    if (!d)
        return QMetaType();
    return static_cast<QPropertyBindingPrivate *>(d.get())->valueMetaType();
}

QPropertyBindingData::~QPropertyBindingData()
{
    QPropertyBindingDataPointer d{this};
    for (auto observer = d.firstObserver(); observer;) {
        auto next = observer.nextObserver();
        observer.unlink();
        observer = next;
    }
    if (auto binding = d.bindingPtr())
        binding->unlinkAndDeref();
}

QUntypedPropertyBinding QPropertyBindingData::setBinding(const QUntypedPropertyBinding &binding,
                                                  QUntypedPropertyData *propertyDataPtr,
                                                  QPropertyObserverCallback staticObserverCallback,
                                                  QtPrivate::QPropertyBindingWrapper guardCallback)
{
    QPropertyBindingPrivatePtr oldBinding;
    QPropertyBindingPrivatePtr newBinding = binding.d;

    QPropertyBindingDataPointer d{this};
    QPropertyObserverPointer observer;

    if (auto *existingBinding = d.bindingPtr()) {
        if (existingBinding == newBinding.data())
            return QUntypedPropertyBinding(static_cast<QPropertyBindingPrivate *>(oldBinding.data()));
        if (existingBinding->isEagerlyUpdating()) {
            existingBinding->setError({QPropertyBindingError::BindingLoop, QStringLiteral("Binding set during binding evaluation!")});
            return QUntypedPropertyBinding(static_cast<QPropertyBindingPrivate *>(oldBinding.data()));
        }
        oldBinding = QPropertyBindingPrivatePtr(existingBinding);
        observer = static_cast<QPropertyBindingPrivate *>(oldBinding.data())->takeObservers();
        static_cast<QPropertyBindingPrivate *>(oldBinding.data())->unlinkAndDeref();
        d_ptr = 0;
    } else {
        observer = d.firstObserver();
    }

    if (newBinding) {
        newBinding.data()->addRef();
        d_ptr = reinterpret_cast<quintptr>(newBinding.data());
        d_ptr |= BindingBit;
        auto newBindingRaw = static_cast<QPropertyBindingPrivate *>(newBinding.data());
        newBindingRaw->setDirty(true);
        newBindingRaw->setProperty(propertyDataPtr);
        if (observer)
            newBindingRaw->prependObserver(observer);
        newBindingRaw->setStaticObserver(staticObserverCallback, guardCallback);
        if (newBindingRaw->requiresEagerEvaluation()) {
            newBindingRaw->setEagerlyUpdating(true);
            auto changed = newBindingRaw->evaluateIfDirtyAndReturnTrueIfValueChanged(propertyDataPtr);
            if (changed)
                observer.notify(newBindingRaw, propertyDataPtr, /*knownToHaveChanged=*/true);
            newBindingRaw->setEagerlyUpdating(false);
        }
    } else if (observer) {
        d.setObservers(observer.ptr);
    } else {
        d_ptr &= ~QPropertyBindingData::BindingBit;
    }

    if (oldBinding)
        static_cast<QPropertyBindingPrivate *>(oldBinding.data())->detachFromProperty();

    return QUntypedPropertyBinding(static_cast<QPropertyBindingPrivate *>(oldBinding.data()));
}

QPropertyBindingData::QPropertyBindingData(QPropertyBindingData &&other) : d_ptr(std::exchange(other.d_ptr, 0))
{
    QPropertyBindingDataPointer d{this};
    d.fixupFirstObserverAfterMove();
}

static thread_local QBindingStatus bindingStatus;

BindingEvaluationState::BindingEvaluationState(QPropertyBindingPrivate *binding, QBindingStatus *status)
    : binding(binding)
{
    QBindingStatus *s = status;
    if (!s)
        s = &bindingStatus;
    // store a pointer to the currentBindingEvaluationState to avoid a TLS lookup in
    // the destructor (as these come with a non zero cost)
    currentState = &s->currentlyEvaluatingBinding;
    previousState = *currentState;
    *currentState = this;
    binding->clearDependencyObservers();
}

CompatPropertySafePoint::CompatPropertySafePoint(QBindingStatus *status, QUntypedPropertyData *property)
    : property(property)
{
    // store a pointer to the currentBindingEvaluationState to avoid a TLS lookup in
    // the destructor (as these come with a non zero cost)
    currentState = &status->currentCompatProperty;
    previousState = *currentState;
    *currentState = this;

    currentlyEvaluatingBindingList = &bindingStatus.currentlyEvaluatingBinding;
    bindingState = *currentlyEvaluatingBindingList;
    *currentlyEvaluatingBindingList = nullptr;
}

QPropertyBindingPrivate *QPropertyBindingPrivate::currentlyEvaluatingBinding()
{
    auto currentState = bindingStatus.currentlyEvaluatingBinding ;
    return currentState ? currentState->binding : nullptr;
}

void QPropertyBindingData::evaluateIfDirty(const QUntypedPropertyData *property) const
{
    QPropertyBindingDataPointer d{this};
    QPropertyBindingPrivate *binding = d.bindingPtr();
    if (!binding)
        return;
    binding->evaluateIfDirtyAndReturnTrueIfValueChanged(property);
}

void QPropertyBindingData::removeBinding_helper()
{
    QPropertyBindingDataPointer d{this};

    auto *existingBinding = d.bindingPtr();
    Q_ASSERT(existingBinding);

    auto observer = existingBinding->takeObservers();
    d_ptr = 0;
    if (observer)
        d.setObservers(observer.ptr);
    existingBinding->unlinkAndDeref();
}

void QPropertyBindingData::registerWithCurrentlyEvaluatingBinding() const
{
    auto currentState = bindingStatus.currentlyEvaluatingBinding;
    if (!currentState)
        return;
    registerWithCurrentlyEvaluatingBinding_helper(currentState);
}


void QPropertyBindingData::registerWithCurrentlyEvaluatingBinding_helper(BindingEvaluationState *currentState) const
{
    QPropertyBindingDataPointer d{this};

    QPropertyObserverPointer dependencyObserver = currentState->binding->allocateDependencyObserver();
    dependencyObserver.setBindingToMarkDirty(currentState->binding);
    dependencyObserver.observeProperty(d);
}

void QPropertyBindingData::notifyObservers(QUntypedPropertyData *propertyDataPtr) const
{
    QPropertyBindingDataPointer d{this};
    if (QPropertyObserverPointer observer = d.firstObserver())
        observer.notify(d.bindingPtr(), propertyDataPtr);
}

void QPropertyBindingData::markDirty()
{
    QPropertyBindingDataPointer d{this};
    if (auto *binding = d.bindingPtr())
        binding->setDirty(true);
}

int QPropertyBindingDataPointer::observerCount() const
{
    int count = 0;
    for (auto observer = firstObserver(); observer; observer = observer.nextObserver())
        ++count;
    return count;
}

QPropertyObserver::QPropertyObserver(ChangeHandler changeHandler)
{
    QPropertyObserverPointer d{this};
    d.setChangeHandler(changeHandler);
}

QPropertyObserver::QPropertyObserver(QUntypedPropertyData *aliasedPropertyPtr)
{
    QPropertyObserverPointer d{this};
    d.setAliasedProperty(aliasedPropertyPtr);
}

/*! \internal
 */
void QPropertyObserver::setSource(const QPropertyBindingData &property)
{
    QPropertyObserverPointer d{this};
    QPropertyBindingDataPointer propPrivate{&property};
    d.observeProperty(propPrivate);
}

QPropertyObserver::~QPropertyObserver()
{
    QPropertyObserverPointer d{this};
    d.unlink();
}

QPropertyObserver::QPropertyObserver(QPropertyObserver &&other) noexcept
{
    bindingToMarkDirty = std::exchange(other.bindingToMarkDirty, {});
    next = std::exchange(other.next, {});
    prev = std::exchange(other.prev, {});
    if (next)
        next->prev = &next;
    if (prev)
        prev.setPointer(this);
}

QPropertyObserver &QPropertyObserver::operator=(QPropertyObserver &&other) noexcept
{
    if (this == &other)
        return *this;

    QPropertyObserverPointer d{this};
    d.unlink();
    bindingToMarkDirty = nullptr;

    bindingToMarkDirty = std::exchange(other.bindingToMarkDirty, {});
    next = std::exchange(other.next, {});
    prev = std::exchange(other.prev, {});
    if (next)
        next->prev = &next;
    if (prev)
        prev.setPointer(this);

    return *this;
}

void QPropertyObserverPointer::unlink()
{
    if (ptr->next.tag() == QPropertyObserver::ObserverNotifiesAlias)
        ptr->aliasedPropertyData = nullptr;
    if (ptr->next)
        ptr->next->prev = ptr->prev;
    if (ptr->prev)
        ptr->prev.setPointer(ptr->next.data());
    ptr->next = nullptr;
    ptr->prev.clear();
}

void QPropertyObserverPointer::setChangeHandler(QPropertyObserver::ChangeHandler changeHandler)
{
    Q_ASSERT(ptr->next.tag() != QPropertyObserver::ObserverIsPlaceholder);
    ptr->changeHandler = changeHandler;
    ptr->next.setTag(QPropertyObserver::ObserverNotifiesChangeHandler);
}

void QPropertyObserverPointer::setAliasedProperty(QUntypedPropertyData *property)
{
    Q_ASSERT(ptr->next.tag() != QPropertyObserver::ObserverIsPlaceholder);
    ptr->aliasedPropertyData = property;
    ptr->next.setTag(QPropertyObserver::ObserverNotifiesAlias);
}

void QPropertyObserverPointer::setBindingToMarkDirty(QPropertyBindingPrivate *binding)
{
    Q_ASSERT(ptr->next.tag() != QPropertyObserver::ObserverIsPlaceholder);
    ptr->bindingToMarkDirty = binding;
    ptr->next.setTag(QPropertyObserver::ObserverNotifiesBinding);
}

/*!
 \internal
 QPropertyObserverNodeProtector is a RAII wrapper which takes care of the internal switching logic
 for QPropertyObserverPointer::notify (described ibidem)
*/
struct [[nodiscard]] QPropertyObserverNodeProtector {
    QPropertyObserverBase m_placeHolder;
    QPropertyObserverNodeProtector(QPropertyObserver *observer)
    {
        // insert m_placeholder after observer into the linked list
        QPropertyObserver *next = observer->next.data();
        m_placeHolder.next = next;
        observer->next = static_cast<QPropertyObserver *>(&m_placeHolder);
        if (next)
            next->prev = &m_placeHolder.next;
        m_placeHolder.prev = &observer->next;
        m_placeHolder.next.setTag(QPropertyObserver::ObserverIsPlaceholder);
    }

    QPropertyObserver *next() const { return m_placeHolder.next.data(); }

    ~QPropertyObserverNodeProtector() {
        QPropertyObserverPointer d{static_cast<QPropertyObserver *>(&m_placeHolder)};
        d.unlink();
    }
};

/*! \internal
  \a propertyDataPtr is a pointer to the observed property's property data
  In case that property has a binding, \a triggeringBinding points to the binding's QPropertyBindingPrivate
  \a alreadyKnownToHaveChanged is an optional parameter, which is needed in the case
  of eager evaluation:
  There, we have already evaluated the binding, and thus the change detection for the
  ObserverNotifiesChangeHandler case would not work. Thus we instead pass the knowledge of
  whether the value has changed we obtained when evaluating the binding eagerly along
 */
void QPropertyObserverPointer::notify(QPropertyBindingPrivate *triggeringBinding, QUntypedPropertyData *propertyDataPtr, bool knownToHaveChanged)
{
    auto observer = const_cast<QPropertyObserver*>(ptr);
    /*
     * The basic idea of the loop is as follows: We iterate over all observers in the linked list,
     * and execute the functionality corresponding to their tag.
     * However, complication arise due to the fact that the triggered operations might modify the list,
     * which includes deletion and move of the current and next nodes.
     * Therefore, we take a few safety precautions:
     * 1. Before executing any action which might modify the list, we insert a placeholder node after the current node.
     *    As that one is stack allocated and owned by us, we can rest assured that it is
     *    still there after the action has executed, and placeHolder->next points to the actual next node in the list.
     *    Note that taking next at the beginning of the loop does not work, as the execuated action might either move
     *    or delete that node.
     * 2. After the triggered action has finished, we can use the next pointer in the placeholder node as a safe way to
     *    retrieve the next node.
     * 3. Some care needs to be taken to avoid infinite recursion with change handlers, so we add an extra test there, that
     *    checks whether we're already have the same change handler in our call stack. This can be done by checking whether
     *    the node after the current one is a placeholder node.
     */
    while (observer) {
        QPropertyObserver *next = observer->next.data();

        char preventBug[1] = {'\0'}; // QTBUG-87245
        Q_UNUSED(preventBug);
        switch (QPropertyObserver::ObserverTag(observer->next.tag())) {
        case QPropertyObserver::ObserverNotifiesChangeHandler:
        {
            auto handlerToCall = observer->changeHandler;
            // prevent recursion
            if (next && next->next.tag() == QPropertyObserver::ObserverIsPlaceholder) {
                observer = next->next.data();
                continue;
            }
            // both evaluateIfDirtyAndReturnTrueIfValueChanged and handlerToCall might modify the list
            QPropertyObserverNodeProtector protector(observer);
            if (!knownToHaveChanged && triggeringBinding) {
                if (!triggeringBinding->evaluateIfDirtyAndReturnTrueIfValueChanged(propertyDataPtr))
                    return;
                knownToHaveChanged = true;
            }
            handlerToCall(observer, propertyDataPtr);
            next = protector.next();
            break;
        }
        case QPropertyObserver::ObserverNotifiesBinding:
        {
            auto bindingToMarkDirty =  observer->bindingToMarkDirty;
            QPropertyObserverNodeProtector protector(observer);
            bindingToMarkDirty->markDirtyAndNotifyObservers();
            next = protector.next();
            break;
        }
        case QPropertyObserver::ObserverNotifiesAlias:
            break;
        case QPropertyObserver::ObserverIsPlaceholder:
            // recursion is already properly handled somewhere else
            break;
        }
        observer = next;
    }
}

void QPropertyObserverPointer::observeProperty(QPropertyBindingDataPointer property)
{
    if (ptr->prev)
        unlink();
    property.addObserver(ptr);
}

QPropertyBindingError::QPropertyBindingError()
{
}

QPropertyBindingError::QPropertyBindingError(Type type, const QString &description)
{
    if (type != NoError) {
        d = new QPropertyBindingErrorPrivate;
        d->type = type;
        d->description = description;
    }
}

QPropertyBindingError::QPropertyBindingError(const QPropertyBindingError &other)
    : d(other.d)
{
}

QPropertyBindingError &QPropertyBindingError::operator=(const QPropertyBindingError &other)
{
    d = other.d;
    return *this;
}

QPropertyBindingError::QPropertyBindingError(QPropertyBindingError &&other)
    : d(std::move(other.d))
{
}

QPropertyBindingError &QPropertyBindingError::operator=(QPropertyBindingError &&other)
{
    d = std::move(other.d);
    return *this;
}

QPropertyBindingError::~QPropertyBindingError()
{
}

QPropertyBindingError::Type QPropertyBindingError::type() const
{
    if (!d)
        return QPropertyBindingError::NoError;
    return d->type;
}

QString QPropertyBindingError::description() const
{
    if (!d)
        return QString();
    return d->description;
}

/*!
  \class QPropertyData
  \inmodule QtCore
  \brief The QPropertyData class is a helper class for properties with automatic property bindings.
  \since 6.0

  \ingroup tools

  QPropertyData\<T\> is a common base class for classes that can hold properties with automatic
  data bindings. It mainly wraps the stored data, and offers low level access to that data.

  The low level access to the data provided by this class bypasses the binding mechanism, and should be
  used with care, as updates to the values will not get propagated to any bindings that depend on this
  property.

  You should usually call value() and setValue() on QProperty<T> or QObjectBindableProperty<T>, not use
  the low level mechanisms provided in this class.
*/

/*! \fn template <typename T> QPropertyData<T>::parameter_type QPropertyData<T>::valueBypassingBindings() const

    Returns the data stored in this property.

    \note As this will bypass any binding evaluation it might return an outdated value if a
    binding is set on this property. Using this method will also not register the property
    access with any currently executing binding.
*/

/*! \fn template <typename T> void QPropertyData<T>::setValueBypassingBindings(parameter_type v)

    Sets the data value stored in this property to \a v.

    \note Using this method will bypass any potential binding registered for this property.
*/

/*! \fn template <typename T> void QPropertyData<T>::setValueBypassingBindings(rvalue_ref v)
    \overload

    Sets the data value stored in this property to \a v.

    \note Using this method will bypass any potential binding registered for this property.
*/

/*!
  \class QUntypedBindable
  \inmodule QtCore
  \brief QUntypedBindable is a uniform interface over bindable properties like \c QProperty\<T\>
         and \c QObjectBindableProperty of any type \c T.
  \since 6.0

  \ingroup tools

  QUntypedBindable is a fully type-erased generic interface to wrap bindable properties.
  You can use it to interact with properties without knowing their type nor caring what
  kind of bindable property they are (e.g. QProperty or QObjectBindableProperty).
  For most use cases, using QBindable\<T\> (which is generic over the property implementation
  but has a fixed type) should be preferred.
*/

/*!
  \fn QUntypedBindable::QUntypedBindable()

  Default-constructs a QUntypedBindable. It is in an invalid state.
  \sa  isValid()
*/

/*!
   \fn template<typename Property> QUntypedBindable::QUntypedBindable(Property *property)

   Constructs a QUntypedBindable from the property \a property. If Property is const,
   the QUntypedBindable will be read only. If \a property is null, the QUntypedBindable
   will be invalid.

   \sa isValid(), isReadOnly()
 */

/*!
   \fn bool QUntypedBindable::isValid() const

   Returns true if the QUntypedBindable is valid. Methods called on an invalid
   QUntypedBindable generally have no effect, unless otherwise noted.
 */

/*!
   \fn bool QUntypedBindable::isReadOnly() const
   \since 6.1

   Returns true if the QUntypedBindable is read-only.
 */

/*!
   \fn bool QUntypedBindable::isBindable() const
   \internal

   Returns true if the underlying property's binding can be queried
   with binding() and, if not read-only, changed with setBinding.
   Only QObjectComputedProperty currently leads to this method returning
   false.

   \sa isReadOnly()
 */

/*!
  \fn QUntypedPropertyBinding QUntypedBindable::makeBinding(const QPropertyBindingSourceLocation &location)

  Creates a binding returning the underlying properties' value, using a specified source \a location.
*/

/*!
  \fn void QUntypedBindable::observe(QPropertyObserver *observer)
  \internal

  Installs the observer on the underlying property.
*/

/*!
  \fn template<typename Functor> QPropertyChangeHandler<Functor> QUntypedBindable::onValueChanged(Functor f)

  Installs \a f as a change handler. Whenever the underlying property changes, \a f will be called, as
  long as the returned \c QPropertyChangeHandler and the property are kept alive.

  \sa template<typename T> QProperty::onValueChanged(), subscribe()
*/

/*!
    \fn template<typename Functor> QPropertyChangeHandler<Functor> QUntypedBindable::subscribe(Functor f)

    Behaves like a call to \a f followed by \c onValueChanged(f),

    \sa onValueChanged()
*/

/*!
  \fn QUntypedPropertyBinding QUntypedBindable::binding() const

  Returns the underlying property's binding if there is any, or a default
  constructed QUntypedPropertyBinding otherwise.

  \sa hasBinding()
*/

/*!
  \fn QUntypedPropertyBinding QUntypedBindable::takeBinding()

  Removes the currently set binding from the property and returns it.
  Returns a default-constructed QUntypedPropertyBinding if no binding is set.

  \since 6.1
*/

/*!
  \fn bool QUntypedBindable::setBinding(const QUntypedPropertyBinding &binding)

  Sets the underlying property's binding to \a binding. This does not have any effect
  if the QUntypedBindable is read-only, null or if \a binding's type does match the
  underlying property's type.

  \return \c true when the binding was successfully set.

  \sa QUntypedPropertyBinding::valueMetaType()
*/

/*!
  \fn bool QUntypedBindable::hasBinding() const

  Returns \c true if the underlying property has a binding.
*/

/*!
  \class QBindable
  \inmodule QtCore
  \brief QBindable is a wrapper class around binding-enabled properties. It allows type-safe
         operations while abstracting the differences between the various property classes away.
  \inherits QUntypedBindable

   \ingroup tools

   QBindable\<T\> helps to integrate Qt's traditional Q_PROPERTY with binding-enabled properties.
   If a property is backed by a QProperty, QObjectBindableProperty or QObjectComputedProperty,
   you can add \c BINDABLE bindablePropertyName to the Q_PROPERTY
   declaration, where bindablePropertyName is a function returning an instance of QBindable
   constructed from the QProperty. The returned QBindable allows users of the property to set
   and query bindings of the property, without having to know the exact kind of binding-enabled
   property used.

   \snippet code/src_corelib_kernel_qproperty.cpp 0
   \snippet code/src_corelib_kernel_qproperty.cpp 3

   \sa QMetaProperty::isBindable, QProperty, QObjectBindableProperty
*/

/*!
  \fn template<typename T> QPropertyBinding<T> QBindable<T>::makeBinding(const QPropertyBindingSourceLocation &location)

  Constructs a binding evaluating to the underlying property's value, using a specified source
  \a location.
*/

/*!
  \fn template <typename T> QPropertyBinding<T> QBindable<T>::binding() const

   Returns the currently set binding of the underlying property. If the property does not
   have a binding, the returned \c QPropertyBinding<T> will be invalid.

   \sa setBinding, hasBinding
   //! \sa QPropertyBinding::isValid()
*/

/*!
  \fn template <typename T> QPropertyBinding<T> QBindable<T>::takeBinding()

   Removes the currently set binding of the underlying property and returns it.
   If the property does not have a binding, the returned \c QPropertyBinding<T> will be invalid.

   \sa binding, setBinding, hasBinding
   //! \sa QPropertyBinding::isValid()
*/


/*!
  \fn template <typename T> void QBindable<T>::setBinding(const QPropertyBinding<T> &binding)

   Sets the underlying property's binding to \a binding. Does nothing if the QBindable is
   read-only or invalid.

   \sa binding, isReadOnly(), isValid()
   //! \sa QPropertyBinding::isValid()
*/

/*!
  \fn  template <typename T> template <typename Functor> QPropertyBinding<T> QBindable<T>::setBinding(Functor f);
  \overload

  Creates a \c QPropertyBinding<T> from \a f, and sets it as the underlying property's binding.
*/

/*!
  \fn template <typename T> T QBindable<T>::value() const

  Returns the underlying property's current value. If the QBindable is invalid,
  a default constructed \c T is returned.

  \sa isValid()
*/

/*!
  \fn template <typename T> void QBindable<T>::setValue(const T &value)

  Sets the underlying property's value to \a value. This removes any currenltly set
  binding from it. This function has no effect if the QBindable is read-only or invalid.

  \sa isValid(), isReadOnly(), setBinding()
*/

/*!
  \class QProperty
  \inmodule QtCore
  \brief The QProperty class is a template class that enables automatic property bindings.
  \since 6.0

  \ingroup tools

  QProperty\<T\> is one of the classes implementing \l {Qt Bindable Properties}.
  It is a container that holds an instance of T. You can assign
  a value to it and you can read it via the value() function or the T conversion
  operator. You can also tie the property to an expression that computes the value
  dynamically, the binding expression. It is represented as a C++ lambda and
  can be used to express relationships between different properties in your
  application.
*/

/*!
  \fn template <typename T> QProperty<T>::QProperty()

  Constructs a property with a default constructed instance of T.
*/

/*!
  \fn template <typename T> explicit QProperty<T>::QProperty(const T &initialValue)

  Constructs a property with the provided \a initialValue.
*/

/*!
  \fn template <typename T> explicit QProperty<T>::QProperty(T &&initialValue)

  Move-Constructs a property with the provided \a initialValue.
*/

/*!
  \fn template <typename T> QProperty<T>::QProperty(QProperty<T> &&other)

  Move-constructs a QProperty instance, making it point at the same object that
  \a other was pointing to.
*/

/*!
  \fn template <typename T> QProperty<T>::QProperty(const QPropertyBinding<T> &binding)

  Constructs a property that is tied to the provided \a binding expression. The
  first time the property value is read, the binding is evaluated. Whenever a
  dependency of the binding changes, the binding will be re-evaluated the next
  time the value of this property is read.
*/

/*!
  \fn template <typename T> template <typename Functor> QProperty<T>::QProperty(Functor &&f)

  Constructs a property that is tied to the provided binding expression \a f. The
  first time the property value is read, the binding is evaluated. Whenever a
  dependency of the binding changes, the binding will be re-evaluated the next
  time the value of this property is read.
*/

/*!
  \fn template <typename T> QProperty<T>::~QProperty()

  Destroys the property.
*/

/*!
  \fn template <typename T> T QProperty<T>::value() const

  Returns the value of the property. This may evaluate a binding expression that
  is tied to this property, before returning the value.
*/

/*!
  \fn template <typename T> void QProperty<T>::setValue(rvalue_ref newValue)
  \fn template <typename T> void QProperty<T>::setValue(parameter_type newValue)

  Assigns \a newValue to this property and removes the property's associated
  binding, if present.
*/

/*!
  \fn template <typename T> QProperty<T> &QProperty<T>::operator=(rvalue_ref newValue)
  \fn template <typename T> QProperty<T> &QProperty<T>::operator=(parameter_type newValue)

  Assigns \a newValue to this property and returns a reference to this QProperty.
*/

/*!
  \fn template <typename T> QProperty<T> &QProperty<T>::operator=(const QPropertyBinding<T> &newBinding)

  Associates the value of this property with the provided \a newBinding
  expression and returns a reference to this property. The first time the
  property value is read, the binding is evaluated. Whenever a dependency of the
  binding changes, the binding will be re-evaluated the next time the value of
  this property is read.
*/

/*!
  \fn template <typename T> void QProperty<T>::markDirty()

  \internal

  Programatically sets the property dirty. Any binding which depends on it will
  be notified.
  This can be useful for properties which do not only depend on bindable properties,
  but also on non-bindable properties or some other state.

  For example, assume we have a \c Circle class, with a non-bindable \c radius property
  and a corresponding \c radiusChanged signal. We now want to create a property for a
  cylinders volume, based on a height \c QProperty and an instance of Circle. To ensure
  that the volume changes, we can call setDirty in a slot  connected to radiusChanged.
  \code
  Circle circle;
  QProperty<double> height;

  QProperty<double> volume;
  volume.setBinding([&]() {return height * std::pi_v<double> * circle.radius() * circle.radius()};
  QOBject::connect(&circle, &Circle::radiusChanged, [&](){volume.markDirty();});
  \endcode

  \note Binding to a QObjectBindableProperty's signal does not make sense in general. Bindings
  across bindable properties get marked dirty automatically.
*/

/*!
  \fn template <typename T> QPropertyBinding<T> QProperty<T>::setBinding(const QPropertyBinding<T> &newBinding)

  Associates the value of this property with the provided \a newBinding
  expression and returns the previously associated binding. The first time the
  property value is read, the binding is evaluated. Whenever a dependency of the
  binding changes, the binding will be re-evaluated the next time the value of
  this property is read.
*/

/*!
  \fn template <typename T> template <typename Functor> QPropertyBinding<T> QProperty<T>::setBinding(Functor f)
  \overload

  Associates the value of this property with the provided functor \a f and
  returns the previously associated binding. The first time the property value
  is read, the binding is evaluated by invoking the call operator () of \a f.
  Whenever a dependency of the binding changes, the binding will be re-evaluated
  the next time the value of this property is read.
*/

/*!
  \fn template <typename T> QPropertyBinding<T> bool QProperty<T>::setBinding(const QUntypedPropertyBinding &newBinding)
  \overload

  Associates the value of this property with the provided \a newBinding
  expression. The first time the property value is read, the binding is evaluated.
  Whenever a dependency of the binding changes, the binding will be re-evaluated
  the next time the value of this property is read.

  Returns true if the type of this property is the same as the type the binding
  function returns; false otherwise.
*/

/*!
  \fn template <typename T> QPropertyBinding<T> QProperty<T>::binding() const

  Returns the binding expression that is associated with this property. A
  default constructed QPropertyBinding<T> will be returned if no such
  association exists.
*/

/*!
  \fn template <typename T> QPropertyBinding<T> QProperty<T>::takeBinding()

  Disassociates the binding expression from this property and returns it. After
  calling this function, the value of the property will only change if you
  assign a new value to it, or when a new binding is set.
*/

/*!
  \fn template <typename T> template <typename Functor> QPropertyChangeHandler<T, Functor> QProperty<T>::onValueChanged(Functor f)

  Registers the given functor \a f as a callback that shall be called whenever
  the value of the property changes.

  The callback \a f is expected to be a type that has a plain call operator () without any
  parameters. This means that you can provide a C++ lambda expression, an std::function
  or even a custom struct with a call operator.

  The returned property change handler object keeps track of the registration. When it
  goes out of scope, the callback is de-registered.
*/

/*!
  \fn template <typename T> template <typename Functor> QPropertyChangeHandler<T, Functor> QProperty<T>::subscribe(Functor f)

  Subscribes the given functor \a f as a callback that is called immediately and whenever
  the value of the property changes in the future.

  The callback \a f is expected to be a type that has a plain call operator () without any
  parameters. This means that you can provide a C++ lambda expression, an std::function
  or even a custom struct with a call operator.

  The returned property change handler object keeps track of the subscription. When it
  goes out of scope, the callback is unsubscribed.
*/

/*!
  \fn template <typename T> QtPrivate::QPropertyBindingData &QProperty<T>::bindingData() const
  \internal
*/

/*!
  \class QObjectBindableProperty
  \inmodule QtCore
  \brief The QObjectBindableProperty class is a template class that enables automatic property bindings
         for property data stored in QObject derived classes.
  \since 6.0

  \ingroup tools

  QObjectBindableProperty is a generic container that holds an
  instance of T and behaves mostly like \l QProperty.
  It is one of the classes implementing \l {Qt Bindable Properties}.
  The extra template
  parameters are used to identify the surrounding class and a member function of
  that class. The member function will be called whenever the value held by the
  property changes.

  You can use QObjectBindableProperty to add binding support to code that uses Q_PROPERTY.
  The getter and setter methods are easy to adapt for accessing a \l QObjectBindableProperty
  rather than the plain value. In order to invoke the change signal on property changes, use
  QObjectBindableProperty and pass the change signal as a callback.

  QObjectBindableProperty is usually not used directly, instead an instance of it is created by
  using the Q_OBJECT_BINDABLE_PROPERTY macro.

  Use the Q_OBJECT_BINDABLE_PROPERTY macro in the class declaration to declare
  the property as bindable.

  \snippet code/src_corelib_kernel_qproperty.cpp 0

  If you need to directly initialize the property with some non-default value,
  you can use the Q_OBJECT_BINDABLE_PROPERTY_WITH_ARGS macro. It accepts a
  value for the initialization as one of its parameters.

  \snippet code/src_corelib_kernel_qproperty.cpp 1

  Q_OBJECT_BINDABLE_PROPERTY_WITH_ARGS does not support multiple arguments
  directly. If your property requires multiple arguments for initialization,
  please explicitly call the specific constructor.

  \snippet code/src_corelib_kernel_qproperty.cpp 2

  If the property does not need a changed notification, you can leave out the
  "NOFITY xChanged" in the Q_PROPERTY macro as well as the last argument
  of the Q_OBJECT_BINDABLE_PROPERTY and Q_OBJECT_BINDABLE_PROPERTY_WITH_ARGS
  macros.
*/

/*!
  \macro Q_OBJECT_BINDABLE_PROPERTY(containingClass, type, name, signal)
  \since 6.0
  \relates QObjectBindableProperty
  \brief Declares a \l QObjectBindableProperty inside \a containingClass
  of type \a type with name \a name. If the optional argument \a signal is given,
  this signal will be emitted when the property is marked dirty.

  \sa {Qt's Property System}, {Qt Bindable Properties}
*/

/*!
  \macro Q_OBJECT_BINDABLE_PROPERTY_WITH_ARGS(containingClass, type, name, initialvalue, signal)
  \since 6.0
  \relates QObjectBindableProperty
  \brief Declares a \l QObjectBindableProperty inside \a containingClass
  of type \a type with name \a name which is initialized to \a initialvalue.
  If the optional argument \a signal is given, this signal will be emitted when
  the property is marked dirty.

  \sa {Qt's Property System}, {Qt Bindable Properties}
*/

/*!
  \fn template <typename Class, typename T, auto offset, auto Callback> QObjectBindableProperty<Class, T, offset, Callback>::QObjectBindableProperty()

  Constructs a property with a default constructed instance of T.
*/

/*!
  \fn template <typename Class, typename T, auto offset, auto Callback> explicit QObjectBindableProperty<Class, T, offset, Callback>::QObjectBindableProperty(const T &initialValue)

  Constructs a property with the provided \a initialValue.
*/

/*!
  \fn template <typename Class, typename T, auto offset, auto Callback> explicit QObjectBindableProperty<Class, T, offset, Callback>::QObjectBindableProperty(T &&initialValue)

  Move-Constructs a property with the provided \a initialValue.
*/

/*!
  \fn template <typename Class, typename T, auto offset, auto Callback> QObjectBindableProperty<Class, T, offset, Callback>::QObjectBindableProperty(Class *owner, const QPropertyBinding<T> &binding)

  Constructs a property that is tied to the provided \a binding expression. The
  first time the property value is read, the binding is evaluated. Whenever a
  dependency of the binding changes, the binding will be re-evaluated the next
  time the value of this property is read. When the property value changes \a
  owner is notified via the Callback function.
*/

/*!
  \fn template <typename Class, typename T, auto offset, auto Callback> QObjectBindableProperty<Class, T, offset, Callback>::QObjectBindableProperty(Class *owner, QPropertyBinding<T> &&binding)

  Constructs a property that is tied to the provided \a binding expression. The
  first time the property value is read, the binding is evaluated. Whenever a
  dependency of the binding changes, the binding will be re-evaluated the next
  time the value of this property is read. When the property value changes \a
  owner is notified via the Callback function.
*/


/*!
  \fn template <typename Class, typename T, auto offset, auto Callback> template <typename Functor> QObjectBindableProperty<Class, T, offset, Callback>::QObjectBindableProperty(Functor &&f)

  Constructs a property that is tied to the provided binding expression \a f. The
  first time the property value is read, the binding is evaluated. Whenever a
  dependency of the binding changes, the binding will be re-evaluated the next
  time the value of this property is read.
*/

/*!
  \fn template <typename Class, typename T, auto offset, auto Callback> QObjectBindableProperty<Class, T, offset, Callback>::~QObjectBindableProperty()

  Destroys the property.
*/

/*!
  \fn template <typename Class, typename T, auto offset, auto Callback> T QObjectBindableProperty<Class, T, offset, Callback>::value() const

  Returns the value of the property. This may evaluate a binding expression that
  is tied to this property, before returning the value.
*/

/*!
  \fn template <typename Class, typename T, auto offset, auto Callback> void QObjectBindableProperty<Class, T, offset, Callback>::setValue(parameter_type newValue)
  \fn template <typename Class, typename T, auto offset, auto Callback> void QObjectBindableProperty<Class, T, offset, Callback>::setValue(rvalue_ref newValue)

  Assigns \a newValue to this property and removes the property's associated
  binding, if present. If the property value changes as a result, calls the
  Callback function on \a owner.
*/

/*!
  \fn template <typename Class, typename T, auto offset, auto Callback> void QObjectBindableProperty<Class, T, offset, Callback>::markDirty()
  \internal

  Programatically sets the property dirty. Any binding which depend on it will
  be notified.
  This can be useful for properties which do not only depend on bindable properties,
  but also on non-bindable properties or some other state.

  \sa QProperty::markDirty()
*/

/*!
  \fn template <typename Class, typename T, auto offset, auto Callback> QPropertyBinding<T> QObjectBindableProperty<Class, T, offset, Callback>::setBinding(const QPropertyBinding<T> &newBinding)

  Associates the value of this property with the provided \a newBinding
  expression and returns the previously associated binding. The first time the
  property value is read, the binding is evaluated. Whenever a dependency of the
  binding changes, the binding will be re-evaluated the next time the value of
  this property is read. When the property value changes, the owner is notified
  via the Callback function.
*/

/*!
  \fn template <typename Class, typename T, auto offset, auto Callback> template <typename Functor> QPropertyBinding<T> QObjectBindableProperty<Class, T, offset, Callback>::setBinding(Functor f)
  \overload

  Associates the value of this property with the provided functor \a f and
  returns the previously associated binding. The first time the property value
  is read, the binding is evaluated by invoking the call operator () of \a f.
  Whenever a dependency of the binding changes, the binding will be re-evaluated
  the next time the value of this property is read. When the property value
  changes, the owner is notified via the Callback function.
*/

/*!
  \fn template <typename Class, typename T, auto offset, auto Callback> QPropertyBinding<T> bool QObjectBindableProperty<Class, T, offset, Callback>::setBinding(const QUntypedPropertyBinding &newBinding)
  \overload

  Associates the value of this property with the provided \a newBinding
  expression. The first time the property value is read, the binding is evaluated.
  Whenever a dependency of the binding changes, the binding will be re-evaluated
  the next time the value of this property is read.

  Returns \c true if the type of this property is the same as the type the binding
  function returns; \c false otherwise.
*/

/*!
  \fn template <typename Class, typename T, auto offset, auto Callback> bool QObjectBindableProperty<Class, T, offset, Callback>::hasBinding() const

  Returns true if the property is associated with a binding; false otherwise.
*/


/*!
  \fn template <typename Class, typename T, auto offset, auto Callback> QPropertyBinding<T> QObjectBindableProperty<Class, T, offset, Callback>::binding() const

  Returns the binding expression that is associated with this property. A
  default constructed QPropertyBinding<T> will be returned if no such
  association exists.
*/

/*!
  \fn template <typename Class, typename T, auto offset, auto Callback> QPropertyBinding<T> QObjectBindableProperty<Class, T, offset, Callback>::takeBinding()

  Disassociates the binding expression from this property and returns it. After
  calling this function, the value of the property will only change if you
  assign a new value to it, or when a new binding is set.
*/

/*!
  \fn template <typename Class, typename T, auto offset, auto Callback> template <typename Functor> QPropertyChangeHandler<T, Functor> QObjectBindableProperty<Class, T, offset, Callback>::onValueChanged(Functor f)

  Registers the given functor \a f as a callback that shall be called whenever
  the value of the property changes.

  The callback \a f is expected to be a type that has a plain call operator () without any
  parameters. This means that you can provide a C++ lambda expression, an std::function
  or even a custom struct with a call operator.

  The returned property change handler object keeps track of the registration. When it
  goes out of scope, the callback is de-registered.
*/

/*!
  \fn template <typename Class, typename T, auto offset, auto Callback> template <typename Functor> QPropertyChangeHandler<T, Functor> QObjectBindableProperty<Class, T, offset, Callback>::subscribe(Functor f)

  Subscribes the given functor \a f as a callback that is called immediately and whenever
  the value of the property changes in the future.

  The callback \a f is expected to be a type that has a plain call operator () without any
  parameters. This means that you can provide a C++ lambda expression, an std::function
  or even a custom struct with a call operator.

  The returned property change handler object keeps track of the subscription. When it
  goes out of scope, the callback is unsubscribed.
*/

/*!
  \fn template <typename T> QtPrivate::QPropertyBase &QObjectBindableProperty<Class, T, offset, Callback>::propertyBase() const
  \internal
*/

/*!
  \class QPropertyChangeHandler
  \inmodule QtCore
  \brief The QPropertyChangeHandler class controls the lifecycle of change callback installed on a QProperty.

  \ingroup tools

  QPropertyChangeHandler\<PropertyType, Functor\> is created when registering a
  callback on a QProperty to listen to changes to the property's value, using QProperty::onValueChanged
  and QProperty::subscribe. As long as the change handler is alive, the callback remains installed.

  A handler instance can be transferred between C++ scopes using move semantics.
*/

/*!
  \class QPropertyAlias
  \inmodule QtCore
  \internal

  \brief The QPropertyAlias class is a safe alias for a QProperty with same template parameter.

  \ingroup tools

  QPropertyAlias\<T\> wraps a pointer to a QProperty\<T\> and automatically
  invalidates itself when the QProperty\<T\> is destroyed. It forwards all
  method invocations to the wrapped property. For example:

  \code
    QProperty<QString> *name = new QProperty<QString>("John");
    QProperty<int> age(41);

    QPropertyAlias<QString> nameAlias(name);
    QPropertyAlias<int> ageAlias(&age);

    QProperty<QString> fullname;
    fullname.setBinding([&]() { return nameAlias.value() + " age: " + QString::number(ageAlias.value()); });

    qDebug() << fullname.value(); // Prints "John age: 41"

    *name = "Emma"; // Marks binding expression as dirty

    qDebug() << fullname.value(); // Re-evaluates the binding expression and prints "Emma age: 41"

    // Birthday is coming up
    ageAlias.setValue(age.value() + 1); // Writes the age property through the alias

    qDebug() << fullname.value(); // Re-evaluates the binding expression and prints "Emma age: 42"

    delete name; // Leaves the alias in an invalid, but accessible state
    nameAlias.setValue("Eve"); // Ignored: nameAlias carries a default-constructed QString now

    ageAlias.setValue(92);
    qDebug() << fullname.value(); // Re-evaluates the binding expression and prints " age: 92"
  \endcode
*/

/*!
  \fn template <typename T> QPropertyAlias<T>::QPropertyAlias(QProperty<T> *property)

  Constructs a property alias for the given \a property.
*/

/*!
  \fn template <typename T> explicit QPropertyAlias<T>::QPropertyAlias(QPropertyAlias<T> *alias)

  Constructs a property alias for the property aliased by \a alias.
*/

/*!
  \fn template <typename T> T QPropertyAlias<T>::value() const

  Returns the value of the aliased property. This may evaluate a binding
  expression that is tied to the property, before returning the value.
*/

/*!
  \fn template <typename T> QPropertyAlias<T>::operator T() const

  Returns the value of the aliased property. This may evaluate a binding
  expression that is tied to the property, before returning the value.
*/

/*!
  \fn template <typename T> void QPropertyAlias<T>::setValue(const T &newValue)

  Assigns \a newValue to the aliased property and removes the property's
  associated binding, if present.
*/

/*!
  \fn template <typename T> QPropertyAlias<T> &QPropertyAlias<T>::operator=(const T &newValue)

  Assigns \a newValue to the aliased property and returns a reference to this
  QPropertyAlias.
*/

/*!
  \fn template <typename T> QPropertyAlias<T> &QPropertyAlias<T>::operator=(T &&newValue)
  \overload

  Assigns \a newValue to the aliased property and returns a reference to this
  QPropertyAlias.
*/

/*!
  \fn template <typename T> QPropertyAlias<T> &QPropertyAlias<T>::operator=(const QPropertyBinding<T> &newBinding)
  \overload

  Associates the value of the aliased property with the provided \a newBinding
  expression and returns a reference to this alias. The first time the
  property value is read, either from the property itself or from any alias, the
  binding is evaluated. Whenever a dependency of the binding changes, the
  binding will be re-evaluated the next time the value of this property is read.
*/

/*!
  \fn template <typename T> QPropertyBinding<T> QPropertyAlias<T>::setBinding(const QPropertyBinding<T> &newBinding)

  Associates the value of the aliased property with the provided \a newBinding
  expression and returns any previous binding the associated with the aliased
  property. The first time the property value is read, either from the property
  itself or from any alias, the binding is evaluated. Whenever a dependency of
  the binding changes, the binding will be re-evaluated the next time the value
  of this property is read.

  Returns any previous binding associated with the property, or a
  default-constructed QPropertyBinding<T>.
*/

/*!
  \fn template <typename T> QPropertyBinding<T> bool QPropertyAlias<T>::setBinding(const QUntypedPropertyBinding &newBinding)
  \overload

  Associates the value of the aliased property with the provided \a newBinding
  expression. The first time the property value is read, either from the
  property itself or from any alias, the binding is evaluated. Whenever a
  dependency of the binding changes, the binding will be re-evaluated the next
  time the value of this property is read.

  Returns true if the type of this property is the same as the type the binding
  function returns; false otherwise.
*/

/*!
  \fn template <typename T> template <typename Functor> QPropertyBinding<T> QPropertyAlias<T>::setBinding(Functor f)
  \overload

  Associates the value of the aliased property with the provided functor \a f
  expression. The first time the property value is read, either from the
  property itself or from any alias, the binding is evaluated. Whenever a
  dependency of the binding changes, the binding will be re-evaluated the next
  time the value of this property is read.

  Returns any previous binding associated with the property, or a
  default-constructed QPropertyBinding<T>.
*/

/*!
  \fn template <typename T> bool QPropertyAlias<T>::hasBinding() const

  Returns true if the aliased property is associated with a binding; false
  otherwise.
*/

/*!
  \fn template <typename T> QPropertyBinding<T> QPropertyAlias<T>::binding() const

  Returns the binding expression that is associated with the aliased property. A
  default constructed QPropertyBinding<T> will be returned if no such
  association exists.
*/

/*!
  \fn template <typename T> QPropertyBinding<T> QPropertyAlias<T>::takeBinding()

  Disassociates the binding expression from the aliased property and returns it.
  After calling this function, the value of the property will only change if
  you assign a new value to it, or when a new binding is set.
*/

/*!
  \fn template <typename T> template <typename Functor> QPropertyChangeHandler<T, Functor> QPropertyAlias<T>::onValueChanged(Functor f)

  Registers the given functor \a f as a callback that shall be called whenever
  the value of the aliased property changes.

  The callback \a f is expected to be a type that has a plain call operator () without any
  parameters. This means that you can provide a C++ lambda expression, an std::function
  or even a custom struct with a call operator.

  The returned property change handler object keeps track of the registration. When it
  goes out of scope, the callback is de-registered.
*/

/*!
  \fn template <typename T> template <typename Functor> QPropertyChangeHandler<T, Functor> QPropertyAlias<T>::subscribe(Functor f)

  Subscribes the given functor \a f as a callback that is called immediately and whenever
  the value of the aliased property changes in the future.

  The callback \a f is expected to be a type that has a plain call operator () without any
  parameters. This means that you can provide a C++ lambda expression, an std::function
  or even a custom struct with a call operator.

  The returned property change handler object keeps track of the subscription. When it
  goes out of scope, the callback is unsubscribed.
*/

/*!
  \fn template <typename T> bool QPropertyAlias<T>::isValid() const

  Returns true if the aliased property still exists; false otherwise.

  If the aliased property doesn't exist, all other method calls are ignored.
*/

struct QBindingStorageData
{
    size_t size = 0;
    size_t used = 0;
    // Pair[] pairs;
};

struct QBindingStoragePrivate
{
    // This class basically implements a simple and fast hash map to store bindings for a QObject
    // The reason that we're not using QHash is that QPropertyBindingData can not be copied, only
    // moved. That doesn't work well together with an implicitly shared class.
    struct Pair
    {
        QUntypedPropertyData *data;
        QPropertyBindingData bindingData;
    };
    static_assert(alignof(Pair) == alignof(void *));
    static_assert(alignof(size_t) == alignof(void *));

    QBindingStorageData *&d;

    static inline Pair *pairs(QBindingStorageData *dd)
    {
        Q_ASSERT(dd);
        return reinterpret_cast<Pair *>(dd + 1);
    }
    void reallocate(size_t newSize)
    {
        Q_ASSERT(!d || newSize > d->size);
        size_t allocSize = sizeof(QBindingStorageData) + newSize*sizeof(Pair);
        void *nd = malloc(allocSize);
        memset(nd, 0, allocSize);
        QBindingStorageData *newData = new (nd) QBindingStorageData;
        newData->size = newSize;
        if (!d) {
            d = newData;
            return;
        }
        newData->used = d->used;
        Pair *p = pairs(d);
        for (size_t i = 0; i < d->size; ++i, ++p) {
            if (p->data) {
                Pair *pp = pairs(newData);
                Q_ASSERT(newData->size && (newData->size & (newData->size - 1)) == 0); // size is a power of two
                size_t index = qHash(p->data) & (newData->size - 1);
                while (pp[index].data) {
                    ++index;
                    if (index == newData->size)
                        index = 0;
                }
                new (pp + index) Pair{p->data, QPropertyBindingData(std::move(p->bindingData))};
            }
        }
        // data has been moved, no need to call destructors on old Pairs
        free(d);
        d = newData;
    }

    QBindingStoragePrivate(QBindingStorageData *&_d) : d(_d) {}

    QPropertyBindingData *get(const QUntypedPropertyData *data)
    {
        Q_ASSERT(d);
        Q_ASSERT(d->size && (d->size & (d->size - 1)) == 0); // size is a power of two
        size_t index = qHash(data) & (d->size - 1);
        Pair *p = pairs(d);
        while (p[index].data) {
            if (p[index].data == data)
                return &p[index].bindingData;
            ++index;
            if (index == d->size)
                index = 0;
        }
        return nullptr;
    }
    QPropertyBindingData *get(QUntypedPropertyData *data, bool create)
    {
        if (!d) {
            if (!create)
                return nullptr;
            reallocate(8);
        }
        else if (d->used*2 >= d->size)
            reallocate(d->size*2);
        Q_ASSERT(d->size && (d->size & (d->size - 1)) == 0); // size is a power of two
        size_t index = qHash(data) & (d->size - 1);
        Pair *p = pairs(d);
        while (p[index].data) {
            if (p[index].data == data)
                return &p[index].bindingData;
            ++index;
            if (index == d->size)
                index = 0;
        }
        if (!create)
            return nullptr;
        ++d->used;
        new (p + index) Pair{data, QPropertyBindingData()};
        return &p[index].bindingData;
    }

    void destroy()
    {
        if (!d)
            return;
        Pair *p = pairs(d);
        for (size_t i = 0; i < d->size; ++i) {
            if (p->data)
                p->~Pair();
            ++p;
        }
        free(d);
    }
};

/*!
    \class QBindingStorage
    \internal

    QBindingStorage acts as a storage for property binding related data in QObject.
    Any property in a QObject can be made bindable by using the Q_OBJECT_BINDABLE_PROPERTY
    macro to declare it. A setter and a getter for the property and a declaration using
    Q_PROPERTY have to be made as usual.
    Binding related data will automatically be stored within the QBindingStorage
    inside the QObject.
*/

QBindingStorage::QBindingStorage()
{
    bindingStatus = &QT_PREPEND_NAMESPACE(bindingStatus);
    Q_ASSERT(bindingStatus);
}

QBindingStorage::~QBindingStorage()
{
    QBindingStoragePrivate(d).destroy();
}

void QBindingStorage::maybeUpdateBindingAndRegister_helper(const QUntypedPropertyData *data) const
{
    Q_ASSERT(bindingStatus);
    QUntypedPropertyData *dd = const_cast<QUntypedPropertyData *>(data);
    auto storage = QBindingStoragePrivate(d).get(dd, /*create=*/ bindingStatus->currentlyEvaluatingBinding != nullptr);
    if (!storage)
        return;
    if (auto *binding = storage->binding())
        binding->evaluateIfDirtyAndReturnTrueIfValueChanged(const_cast<QUntypedPropertyData *>(data), bindingStatus);
    storage->registerWithCurrentlyEvaluatingBinding(bindingStatus->currentlyEvaluatingBinding);
}

QPropertyBindingData *QBindingStorage::bindingData_helper(const QUntypedPropertyData *data) const
{
    return QBindingStoragePrivate(d).get(data);
}

QPropertyBindingData *QBindingStorage::bindingData_helper(QUntypedPropertyData *data, bool create)
{
    return QBindingStoragePrivate(d).get(data, create);
}


BindingEvaluationState *suspendCurrentBindingStatus()
{
    auto ret = bindingStatus.currentlyEvaluatingBinding;
    bindingStatus.currentlyEvaluatingBinding = nullptr;
    return ret;
}

void restoreBindingStatus(BindingEvaluationState *status)
{
    bindingStatus.currentlyEvaluatingBinding = status;
}

namespace QtPrivate {
/*!
    \internal
    This function can be used to detect whether we are currently
    evaluating a binding. This can e.g. be used to defer the allocation
    of extra data for a QPropertyBindingStorage in a getter.
    Note that this function accesses TLS storage, and is therefore soemwhat
    costly to call.
 */
bool isAnyBindingEvaluating()
{
    return bindingStatus.currentlyEvaluatingBinding != nullptr;
}
} // namespace QtPrivate end

QT_END_NAMESPACE
